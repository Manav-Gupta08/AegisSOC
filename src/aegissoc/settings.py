from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

_ENV_LINE = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")

SECRET_KEYS = (
    "INDEXER_ADMIN_PASSWORD",
    "INDEXER_KIBANASERVER_PASSWORD",
    "INDEXER_READER_PASSWORD",
    "WAZUH_API_WUI_PASSWORD",
    "WAZUH_API_WAZUH_PASSWORD",
    "WAZUH_API_READER_PASSWORD",
    "WAZUH_ENROLLMENT_PASSWORD",
)

DEFAULT_SETTINGS = {
    "AEGIS_AGENT_BIND": "127.0.0.1",
    "AEGIS_DASHBOARD_PORT": "5601",
    "AEGIS_DISK_WARN_PERCENT": "75",
    "AEGIS_DISK_FAIL_PERCENT": "85",
    "AEGIS_ALERT_STALE_MINUTES": "60",
}


def find_repo_root(start: Path | None = None) -> Path:
    here = (start or Path.cwd()).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "deployment" / "wazuh" / "stack.lock.json").is_file():
            return candidate
    raise FileNotFoundError("Not inside an AegisSOC checkout (deployment/wazuh/stack.lock.json not found)")


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(text.removeprefix("\ufeff").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE.match(line)
        if not match:
            raise ValueError(f".env line {number} is not KEY=VALUE")
        values[match.group(1)] = match.group(2)
    return values


@dataclass(frozen=True)
class StackLock:
    wazuh_version: str
    compose_project: str
    archive_url: str
    archive_sha256: str
    archive_root: str
    images: dict[str, str]

    @classmethod
    def load(cls, path: Path) -> "StackLock":
        data = json.loads(path.read_text(encoding="utf-8"))
        upstream = data["upstream"]
        sha = upstream["archive_sha256"].lower()
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError(f"{path}: archive_sha256 is not a SHA-256 hex digest")
        return cls(
            wazuh_version=data["wazuh_version"],
            compose_project=data["compose_project"],
            archive_url=upstream["archive_url"],
            archive_sha256=sha,
            archive_root=upstream["archive_root"],
            images=dict(data["images"]),
        )


@dataclass(frozen=True)
class Paths:
    root: Path

    @property
    def env_file(self) -> Path:
        return self.root / ".env"

    @property
    def lock_file(self) -> Path:
        return self.root / "deployment" / "wazuh" / "stack.lock.json"

    @property
    def override_file(self) -> Path:
        return self.root / "deployment" / "wazuh" / "docker-compose.override.yml"

    @property
    def upstream_dir(self) -> Path:
        return self.root / "deployment" / "wazuh" / "upstream"

    @property
    def runtime_dir(self) -> Path:
        return self.root / "deployment" / "wazuh" / "runtime"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports" / "runtime"

    def single_node_dir(self, lock: StackLock) -> Path:
        return self.upstream_dir / lock.archive_root / "single-node"

    def certs_dir(self, lock: StackLock) -> Path:
        return self.single_node_dir(lock) / "config" / "wazuh_indexer_ssl_certs"


@dataclass(frozen=True)
class Context:
    paths: Paths
    lock: StackLock
    env: dict[str, str]

    @classmethod
    def load(cls, root: Path | None = None, require_env: bool = True) -> "Context":
        paths = Paths(root or find_repo_root())
        lock = StackLock.load(paths.lock_file)
        env: dict[str, str] = dict(DEFAULT_SETTINGS)
        if paths.env_file.is_file():
            env.update(parse_env(paths.env_file.read_text(encoding="utf-8")))
        elif require_env:
            raise FileNotFoundError(f"{paths.env_file} not found; run `aegis init-secrets` first")
        return cls(paths=paths, lock=lock, env=env)

    def secret(self, key: str) -> str:
        value = self.env.get(key, "")
        if not value:
            raise KeyError(f"{key} is empty in .env; run `aegis init-secrets`")
        return value

    def secrets(self) -> list[str]:
        return [self.env[k] for k in SECRET_KEYS if self.env.get(k)]

    def int_setting(self, key: str) -> int:
        return int(self.env.get(key, DEFAULT_SETTINGS[key]))
