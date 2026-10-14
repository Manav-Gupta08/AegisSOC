from pathlib import Path

import pytest

from aegissoc.settings import Context, Paths

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A minimal AegisSOC checkout layout with the real lock file."""
    lock_dir = tmp_path / "deployment" / "wazuh"
    lock_dir.mkdir(parents=True)
    (lock_dir / "stack.lock.json").write_text((REPO_ROOT / "deployment" / "wazuh" / "stack.lock.json").read_text())
    return tmp_path


@pytest.fixture
def ctx(repo: Path) -> Context:
    from aegissoc.deploy import init_secrets

    init_secrets(Paths(repo))
    return Context.load(repo)
