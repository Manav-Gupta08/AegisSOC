"""Repository hygiene: tracked files must not contain secrets, private keys, or upstream default credentials."""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from aegissoc.health import DEFAULT_API_CREDENTIALS, DEFAULT_INDEXER_CREDENTIALS

ROOT = Path(__file__).resolve().parents[2]
# Built from health.py so this file does not contain the literal values it searches for.
_UPSTREAM_PASSWORDS = {p for u, p in DEFAULT_API_CREDENTIALS + DEFAULT_INDEXER_CREDENTIALS if p != u}
PATTERNS = {
    "filled-in password variable": re.compile(r"^[A-Z0-9_]*PASSWORD=\S+", re.MULTILINE),
    "private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "upstream default password": re.compile("|".join(re.escape(p) for p in sorted(_UPSTREAM_PASSWORDS))),
}
# The health check intentionally contains upstream defaults: it verifies they are rejected.
ALLOWED = {"upstream default password": {"src/aegissoc/health.py"}}


def tracked_files() -> list[str]:
    if shutil.which("git") is None:
        pytest.skip("git not available")
    out = subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    return out.stdout.splitlines()


def test_no_secrets_in_tracked_files():
    findings = []
    for rel in tracked_files():
        path = ROOT / rel
        if not path.is_file() or path.stat().st_size > 2_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for name, pattern in PATTERNS.items():
            if pattern.search(text) and rel not in ALLOWED.get(name, set()):
                findings.append(f"{rel}: {name}")
    assert not findings, findings


@pytest.mark.parametrize("path", [".env", "cases/x.json", "backups/x/manifest.json", "reports/runtime/x.json",
                                  "deployment/wazuh/runtime/authd.pass", "deployment/wazuh/upstream/x", "x.pem", "notes-local.txt"])
def test_sensitive_paths_are_ignored(path):
    if shutil.which("git") is None:
        pytest.skip("git not available")
    result = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", path])
    assert result.returncode == 0, f"{path} is not git-ignored"
