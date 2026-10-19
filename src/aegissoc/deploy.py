from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import string
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable

from .settings import DEFAULT_SETTINGS, SECRET_KEYS, Context, Paths, StackLock, parse_env

PASSWORD_SYMBOLS = ".-"
# Restricted so values are safe in .env, YAML double quotes, and the upstream entrypoint's sed edits.
SAFE_SECRET = re.compile(r"^[A-Za-z0-9.\-]{16,64}$")
BCRYPT_HASH = re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")
HASH_TOOL = "/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh"
REQUIRED_CERTS = (
    "root-ca.pem",
    "root-ca-manager.pem",
    "admin.pem",
    "admin-key.pem",
    "wazuh.indexer.pem",
    "wazuh.indexer-key.pem",
    "wazuh.manager.pem",
    "wazuh.manager-key.pem",
    "wazuh.dashboard.pem",
    "wazuh.dashboard-key.pem",
)
INDEXER_DATA_VOLUME = "wazuh-indexer-data"

Runner = Callable[..., subprocess.CompletedProcess]


class DeployError(RuntimeError):
    pass


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + PASSWORD_SYMBOLS
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in candidate)
            and any(c.isupper() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in PASSWORD_SYMBOLS for c in candidate)
        ):
            return candidate


def validate_secret(key: str, value: str) -> None:
    if not SAFE_SECRET.match(value):
        raise DeployError(f"{key} must be 16-64 chars of [A-Za-z0-9.-]; regenerate it with `aegis init-secrets`")
    if not (any(c.islower() for c in value) and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value) and any(c in PASSWORD_SYMBOLS for c in value)):
        raise DeployError(f"{key} needs upper, lower, digit and one of {PASSWORD_SYMBOLS!r} (Wazuh API policy)")


def init_secrets(paths: Paths) -> list[str]:
    """Create or complete .env. Existing values are never overwritten."""
    lines = ["# AegisSOC local configuration - generated, never commit."]
    raw_has_bom = paths.env_file.is_file() and paths.env_file.read_bytes().startswith(b"\xef\xbb\xbf")
    if paths.env_file.is_file():
        lines = paths.env_file.read_text(encoding="utf-8-sig").splitlines()
    existing = parse_env("\n".join(lines))

    added: list[str] = []
    for key in SECRET_KEYS:
        if existing.get(key):
            continue
        value = generate_password()
        replaced = False
        for i, line in enumerate(lines):
            if line.strip() == f"{key}=":
                lines[i] = f"{key}={value}"
                replaced = True
                break
        if not replaced:
            lines.append(f"{key}={value}")
        added.append(key)
    for key, value in DEFAULT_SETTINGS.items():
        if key not in existing:
            lines.append(f"{key}={value}")
            added.append(key)

    if added or raw_has_bom:
        write_private(paths.env_file, "\n".join(lines) + "\n")
    return added


def write_private(path: Path, content: str) -> None:
    """Write a file readable only by its owner (POSIX modes; Windows relies on the user-profile ACLs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(content)
    os.chmod(path, 0o600)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_upstream(paths: Paths, lock: StackLock, opener: Callable = urllib.request.urlopen) -> Path:
    target = paths.upstream_dir / lock.archive_root
    if target.is_dir():
        return target

    paths.upstream_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=paths.upstream_dir) as tmp:
        archive = Path(tmp) / "upstream.tar.gz"
        with opener(lock.archive_url, timeout=60) as resp, archive.open("wb") as out:
            shutil.copyfileobj(resp, out)
        actual = _sha256(archive)
        if actual != lock.archive_sha256:
            raise DeployError(
                f"Upstream archive SHA-256 mismatch: expected {lock.archive_sha256}, got {actual}. Refusing to extract."
            )
        extract_dir = Path(tmp) / "x"
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(extract_dir, filter="data")
        extracted = extract_dir / lock.archive_root
        if not (extracted / "single-node" / "docker-compose.yml").is_file():
            raise DeployError("Upstream archive does not contain single-node/docker-compose.yml")
        extracted.rename(target)
    return target


def missing_certs(certs_dir: Path) -> list[str]:
    return [name for name in REQUIRED_CERTS if not (certs_dir / name).is_file()]


def generate_certs(paths: Paths, lock: StackLock, run: Runner = subprocess.run) -> None:
    certs_dir = paths.certs_dir(lock)
    missing = missing_certs(certs_dir)
    if not missing:
        return
    if len(missing) != len(REQUIRED_CERTS) and certs_dir.is_dir():
        raise DeployError(f"Partial certificate set in {certs_dir} (missing {missing}); inspect manually before regenerating")
    run(
        ["docker", "compose", "-p", f"{lock.compose_project}-certs", "-f", "generate-indexer-certs.yml", "run", "--rm", "generator"],
        cwd=paths.single_node_dir(lock),
        check=True,
    )
    still_missing = missing_certs(certs_dir)
    if still_missing:
        raise DeployError(f"Certificate generator did not produce: {still_missing}")


def hash_password(image: str, password: str, run: Runner = subprocess.run) -> str:
    # Password travels via the environment, not argv, so it is absent from process listings.
    result = run(
        [
            "docker", "run", "--rm",
            "-e", "JAVA_HOME=/usr/share/wazuh-indexer/jdk",
            "-e", "AEGIS_PW",
            "--entrypoint", "bash",
            image, "-c", f'{HASH_TOOL} -p "$AEGIS_PW"',
        ],
        env={**os.environ, "AEGIS_PW": password},
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
    )
    for line in reversed(result.stdout.splitlines()):
        if BCRYPT_HASH.match(line.strip()):
            return line.strip()
    raise DeployError("hash.sh did not return a bcrypt hash")


def render_internal_users(admin_hash: str, kibanaserver_hash: str) -> str:
    for value in (admin_hash, kibanaserver_hash):
        if not BCRYPT_HASH.match(value):
            raise DeployError("Refusing to render internal_users.yml with a non-bcrypt hash")
    return f"""---
# Rendered by `aegis prepare`. Upstream demo users (kibanaro, logstash, readall, snapshotrestore) are removed.
_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "{admin_hash}"
  reserved: true
  backend_roles:
  - "admin"
  description: "Indexer administrator (bootstrap and provisioning only)"

kibanaserver:
  hash: "{kibanaserver_hash}"
  reserved: true
  description: "Wazuh dashboard service account"
"""


def render_manager_conf(upstream_conf: str) -> str:
    edits = {
        "<use_password>no</use_password>": "<use_password>yes</use_password>",
        # Manager-container CIS (Amazon Linux) checks are not lab telemetry; they were ~28% of alert volume.
        "<sca>\n    <enabled>yes</enabled>": "<sca>\n    <enabled>no</enabled>",
    }
    for needle, replacement in edits.items():
        if upstream_conf.count(needle) != 1:
            raise DeployError(f"Upstream wazuh_manager.conf layout changed: expected exactly one {needle!r}")
        upstream_conf = upstream_conf.replace(needle, replacement)
    return upstream_conf


def render_dashboard_wazuh_yml(api_password: str) -> str:
    validate_secret("WAZUH_API_WUI_PASSWORD", api_password)
    return f"""hosts:
  - 1513629884013:
      url: "https://wazuh.manager"
      port: 55000
      username: wazuh-wui
      password: "{api_password}"
      run_as: true
"""


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def volume_exists(project: str, volume: str, run: Runner = subprocess.run) -> bool:
    result = run(["docker", "volume", "inspect", f"{project}_{volume}"], capture_output=True, text=True)
    return result.returncode == 0


def prepare(ctx: Context, force_render: bool = False, run: Runner = subprocess.run, log: Callable[[str], None] = print,
            rehash_users: bool = False) -> None:
    for key in SECRET_KEYS:
        validate_secret(key, ctx.secret(key))

    log(f"Fetching wazuh-docker {ctx.lock.wazuh_version} (SHA-256 verified)")
    fetch_upstream(ctx.paths, ctx.lock)

    log("Ensuring stack certificates")
    generate_certs(ctx.paths, ctx.lock, run=run)

    runtime = ctx.paths.runtime_dir
    # Holds secrets; containers read the files through bind mounts, which this directory mode does not affect.
    runtime.mkdir(parents=True, exist_ok=True)
    os.chmod(runtime, 0o700)
    users_file = runtime / "internal_users.yml"
    if rehash_users or not users_file.is_file():
        if volume_exists(ctx.lock.compose_project, INDEXER_DATA_VOLUME, run=run):
            log("WARNING: indexer data volume exists; new internal_users.yml takes effect only after securityadmin.sh (see docs/deployment.md)")
        log("Hashing indexer passwords with the indexer image's hash.sh")
        image = ctx.lock.images["indexer"]
        _write(users_file, render_internal_users(
            hash_password(image, ctx.secret("INDEXER_ADMIN_PASSWORD"), run=run),
            hash_password(image, ctx.secret("INDEXER_KIBANASERVER_PASSWORD"), run=run),
        ))

    upstream_conf = ctx.paths.single_node_dir(ctx.lock) / "config" / "wazuh_cluster" / "wazuh_manager.conf"
    rendered = {
        "wazuh_manager.conf": render_manager_conf(upstream_conf.read_text(encoding="utf-8")),
        "authd.pass": ctx.secret("WAZUH_ENROLLMENT_PASSWORD") + "\n",
        "wazuh.yml": render_dashboard_wazuh_yml(ctx.secret("WAZUH_API_WUI_PASSWORD")),
    }
    for name, content in rendered.items():
        target = runtime / name
        if force_render or not target.is_file():
            _write(target, content)
    log(f"Rendered runtime configuration in {runtime}")


def compose_command(ctx: Context, *args: str) -> list[str]:
    return [
        "docker", "compose",
        "-p", ctx.lock.compose_project,
        "--env-file", str(ctx.paths.env_file),
        "-f", str(ctx.paths.single_node_dir(ctx.lock) / "docker-compose.yml"),
        "-f", str(ctx.paths.override_file),
        *args,
    ]


def compose_env(ctx: Context) -> dict[str, str]:
    return {**os.environ, "AEGIS_RUNTIME_DIR": ctx.paths.runtime_dir.as_posix()}


def guard_compose_args(args: list[str]) -> None:
    if "down" in args and any(a in ("-v", "--volumes") for a in args):
        raise DeployError("Refusing `down --volumes`: AegisSOC tooling never deletes data volumes")


MAX_MAP_COUNT = 262144
MAX_MAP_COUNT_PROC = Path("/proc/sys/vm/max_map_count")


def read_max_map_count(run: Runner = subprocess.run, platform: str = sys.platform,
                       proc: Path = MAX_MAP_COUNT_PROC) -> int | None:
    """The kernel setting the indexer sees: Docker Desktop's VM on Windows, the host kernel on Linux."""
    if platform == "win32":
        result = run(["wsl", "-d", "docker-desktop", "cat", proc.as_posix()], capture_output=True, text=True)
        text = result.stdout if result.returncode == 0 else ""
    else:
        try:
            text = proc.read_text(encoding="ascii")
        except OSError:
            return None
    try:
        return int(text.strip())
    except ValueError:
        return None


def ensure_max_map_count(run: Runner = subprocess.run, log: Callable[[str], None] = print, platform: str = sys.platform,
                         proc: Path = MAX_MAP_COUNT_PROC) -> None:
    current = read_max_map_count(run, platform, proc)
    if current is not None and current >= MAX_MAP_COUNT:
        return
    if platform != "win32":
        # Changing a host kernel setting needs root; AegisSOC never escalates privileges itself.
        raise DeployError(
            f"vm.max_map_count is {current}, the indexer needs >= {MAX_MAP_COUNT}. As root run "
            f"`sysctl -w vm.max_map_count={MAX_MAP_COUNT}` and persist it with "
            f"`echo vm.max_map_count={MAX_MAP_COUNT} > /etc/sysctl.d/99-aegissoc.conf`")
    log(f"Setting vm.max_map_count={MAX_MAP_COUNT} in the docker-desktop WSL distro (was {current})")
    run(["wsl", "-d", "docker-desktop", "sysctl", "-w", f"vm.max_map_count={MAX_MAP_COUNT}"], check=True, capture_output=True)
    if (read_max_map_count(run, platform, proc) or 0) < MAX_MAP_COUNT:
        raise DeployError("vm.max_map_count could not be raised; the indexer will fail to start")


def require_prepared(ctx: Context) -> None:
    if ctx.paths.env_file.read_bytes().startswith(b"\xef\xbb\xbf"):
        raise DeployError(".env has a UTF-8 BOM that Docker Compose misreads; run `aegis init-secrets` to normalize it")
    missing = [n for n in ("internal_users.yml", "wazuh_manager.conf", "authd.pass", "wazuh.yml")
               if not (ctx.paths.runtime_dir / n).is_file()]
    if missing or missing_certs(ctx.paths.certs_dir(ctx.lock)):
        raise DeployError("Stack is not prepared; run `aegis prepare` first")
