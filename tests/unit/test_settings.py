from pathlib import Path

import pytest

from aegissoc.deploy import init_secrets, validate_secret
from aegissoc.settings import SECRET_KEYS, Context, Paths, StackLock, find_repo_root, parse_env


def test_parse_env_ignores_comments_and_blank_lines():
    assert parse_env("# c\n\nA_B=1\nC=x=y\n") == {"A_B": "1", "C": "x=y"}


def test_parse_env_rejects_malformed_line():
    with pytest.raises(ValueError, match="line 2"):
        parse_env("A=1\nnot a pair\n")


def test_parse_env_tolerates_utf8_bom():
    assert parse_env("\ufeffA=1\n") == {"A": "1"}


def test_init_secrets_strips_bom_written_by_editors(repo: Path):
    init_secrets(Paths(repo))
    env_file = repo / ".env"
    env_file.write_bytes(b"\xef\xbb\xbf" + env_file.read_bytes())
    assert init_secrets(Paths(repo)) == []
    assert not env_file.read_bytes().startswith(b"\xef\xbb\xbf")


def test_lock_file_is_valid_and_pinned():
    root = find_repo_root(Path(__file__).parent)
    lock = StackLock.load(Paths(root).lock_file)
    assert lock.wazuh_version in lock.archive_url
    assert all(f":{lock.wazuh_version}@sha256:" in img for img in lock.images.values())


def test_override_images_match_digest_pins():
    import re

    root = find_repo_root(Path(__file__).parent)
    paths = Paths(root)
    override = paths.override_file.read_text()
    pinned = set(re.findall(r"^\s+image:\s*(\S+)$", override, re.MULTILINE))
    assert pinned == set(StackLock.load(paths.lock_file).images.values())


def test_lock_rejects_bad_digest(tmp_path: Path):
    bad = tmp_path / "lock.json"
    bad.write_text('{"wazuh_version":"1","compose_project":"p","images":{},'
                   '"upstream":{"archive_url":"u","archive_sha256":"abc","archive_root":"r"}}')
    with pytest.raises(ValueError, match="SHA-256"):
        StackLock.load(bad)


def test_init_secrets_creates_valid_unique_secrets(repo: Path):
    added = init_secrets(Paths(repo))
    env = parse_env((repo / ".env").read_text())
    assert set(SECRET_KEYS) <= set(added)
    for key in SECRET_KEYS:
        validate_secret(key, env[key])
    assert len({env[k] for k in SECRET_KEYS}) == len(SECRET_KEYS)


def test_init_secrets_never_overwrites_and_fills_empty_keys(repo: Path):
    env_file = repo / ".env"
    env_file.write_text("INDEXER_ADMIN_PASSWORD=Keep.Me.1234567890ab\nWAZUH_API_WUI_PASSWORD=\nAEGIS_AGENT_BIND=10.0.0.1\n")
    init_secrets(Paths(repo))
    text = env_file.read_text()
    env = parse_env(text)
    assert env["INDEXER_ADMIN_PASSWORD"] == "Keep.Me.1234567890ab"
    assert env["WAZUH_API_WUI_PASSWORD"]
    assert text.count("WAZUH_API_WUI_PASSWORD=") == 1
    assert env["AEGIS_AGENT_BIND"] == "10.0.0.1"
    assert init_secrets(Paths(repo)) == []


def test_context_requires_env(repo: Path):
    with pytest.raises(FileNotFoundError, match="init-secrets"):
        Context.load(repo)


def test_context_secrets_lists_only_secret_values(ctx: Context):
    assert len(ctx.secrets()) == len(SECRET_KEYS)
    assert "127.0.0.1" not in ctx.secrets()
