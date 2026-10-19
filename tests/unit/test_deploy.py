import hashlib
import io
import os
import stat
import subprocess
import tarfile
from pathlib import Path

import pytest

from aegissoc import deploy
from aegissoc.deploy import (
    DeployError,
    compose_command,
    fetch_upstream,
    generate_password,
    guard_compose_args,
    hash_password,
    render_dashboard_wazuh_yml,
    render_internal_users,
    render_manager_conf,
    validate_secret,
)
from aegissoc.settings import Paths, StackLock

FAKE_HASH = "$2y$12$" + "a" * 53


def _tarball(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _lock(root: str, sha: str) -> StackLock:
    return StackLock("4.14.8", "aegissoc", "https://example.invalid/a.tgz", sha, root, {"indexer": "img:1"})


def _opener(payload: bytes):
    def opener(url, timeout):
        return io.BytesIO(payload)
    return opener


@pytest.mark.parametrize("_", range(20))
def test_generated_passwords_satisfy_policy(_):
    validate_secret("K", generate_password())


@pytest.mark.parametrize("value", ["short.A1", "NoSymbolsHere12345678", "has$dollar.A1aaaaaaaa", 'quote".A1aaaaaaaaaa'])
def test_validate_secret_rejects_unsafe_values(value):
    with pytest.raises(DeployError):
        validate_secret("K", value)


def test_fetch_upstream_verifies_hash_and_extracts(tmp_path: Path):
    payload = _tarball({"root/single-node/docker-compose.yml": b"services: {}\n"})
    lock = _lock("root", hashlib.sha256(payload).hexdigest())
    target = fetch_upstream(Paths(tmp_path), lock, opener=_opener(payload))
    assert (target / "single-node" / "docker-compose.yml").is_file()
    assert fetch_upstream(Paths(tmp_path), lock, opener=None) == target  # idempotent, no download


def test_fetch_upstream_rejects_hash_mismatch(tmp_path: Path):
    payload = _tarball({"root/single-node/docker-compose.yml": b"x"})
    with pytest.raises(DeployError, match="mismatch"):
        fetch_upstream(Paths(tmp_path), _lock("root", "0" * 64), opener=_opener(payload))
    assert not (tmp_path / "deployment" / "wazuh" / "upstream" / "root").exists()


def test_fetch_upstream_blocks_path_traversal(tmp_path: Path):
    payload = _tarball({"root/single-node/docker-compose.yml": b"x", "../escape.txt": b"pwned"})
    with pytest.raises(tarfile.TarError):
        fetch_upstream(Paths(tmp_path), _lock("root", hashlib.sha256(payload).hexdigest()), opener=_opener(payload))
    assert not list(tmp_path.rglob("escape.txt"))


def test_render_internal_users_drops_demo_users():
    text = render_internal_users(FAKE_HASH, FAKE_HASH)
    for demo in ("kibanaro:", "logstash:", "readall:", "snapshotrestore:"):
        assert demo not in text
    assert "admin:" in text and "kibanaserver:" in text


def test_render_internal_users_rejects_non_bcrypt():
    with pytest.raises(DeployError):
        render_internal_users("plaintext", FAKE_HASH)


def test_render_manager_conf_enables_enrollment_password_and_disables_sca():
    out = render_manager_conf("<auth>\n<use_password>no</use_password>\n</auth>\n<sca>\n    <enabled>yes</enabled>\n</sca>")
    assert "<use_password>yes</use_password>" in out and "no</use_password>" not in out
    assert "<sca>\n    <enabled>no</enabled>" in out


def test_render_manager_conf_fails_on_unexpected_layout():
    with pytest.raises(DeployError, match="layout"):
        render_manager_conf("<auth></auth>")


def test_render_dashboard_yml_contains_password():
    assert 'password: "Abc.def-123456789Xyz"' in render_dashboard_wazuh_yml("Abc.def-123456789Xyz")


def test_hash_password_keeps_secret_out_of_argv():
    calls = {}

    def fake_run(cmd, **kwargs):
        calls["cmd"], calls["env"] = cmd, kwargs["env"]
        return subprocess.CompletedProcess(cmd, 0, stdout=f"**warning**\n{FAKE_HASH}\n", stderr="")

    assert hash_password("img:1", "S3cret.Value-xyz123", run=fake_run) == FAKE_HASH
    assert not any("S3cret.Value-xyz123" in part for part in calls["cmd"])
    assert calls["env"]["AEGIS_PW"] == "S3cret.Value-xyz123"


def test_hash_password_errors_without_hash():
    fake = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="nothing", stderr="")  # noqa: E731
    with pytest.raises(DeployError):
        hash_password("img:1", "x", run=fake)


@pytest.mark.parametrize("args", [["down", "-v"], ["down", "--volumes"]])
def test_guard_refuses_volume_deletion(args):
    with pytest.raises(DeployError):
        guard_compose_args(args)


def test_guard_allows_safe_commands():
    guard_compose_args(["ps"])
    guard_compose_args(["logs", "-f", "wazuh.manager"])


def test_compose_command_uses_project_env_and_override(ctx):
    cmd = compose_command(ctx, "ps")
    assert cmd[:4] == ["docker", "compose", "-p", "aegissoc"]
    assert str(ctx.paths.override_file) in cmd and cmd[-1] == "ps"


def test_partial_certs_are_not_regenerated(ctx):
    certs = ctx.paths.certs_dir(ctx.lock)
    certs.mkdir(parents=True)
    (certs / "root-ca.pem").write_text("x")
    with pytest.raises(DeployError, match="Partial"):
        deploy.generate_certs(ctx.paths, ctx.lock, run=lambda *a, **k: pytest.fail("generator must not run"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_env_file_is_owner_only(ctx):
    ctx.paths.env_file.chmod(0o644)
    ctx.paths.env_file.write_text(ctx.paths.env_file.read_text().replace("AEGIS_RETENTION_DAYS=30\n", ""))
    assert deploy.init_secrets(ctx.paths) == ["AEGIS_RETENTION_DAYS"]
    assert stat.S_IMODE(ctx.paths.env_file.stat().st_mode) == 0o600


def _no_run(*args, **kwargs):
    pytest.fail("must not run a command on this platform")


@pytest.mark.parametrize("value,expected", [("262144\n", 262144), ("65530\n", 65530), ("garbage", None)])
def test_read_max_map_count_on_linux_reads_host_kernel(tmp_path, value, expected):
    proc = tmp_path / "max_map_count"
    proc.write_text(value)
    assert deploy.read_max_map_count(run=_no_run, platform="linux", proc=proc) == expected
    assert deploy.read_max_map_count(run=_no_run, platform="linux", proc=tmp_path / "missing") is None


def test_ensure_max_map_count_on_linux_never_escalates(tmp_path):
    proc = tmp_path / "max_map_count"
    proc.write_text("65530\n")
    with pytest.raises(DeployError, match="sysctl -w vm.max_map_count=262144"):
        deploy.ensure_max_map_count(run=_no_run, log=lambda m: None, platform="linux", proc=proc)
    proc.write_text("262144\n")
    deploy.ensure_max_map_count(run=_no_run, log=lambda m: None, platform="linux", proc=proc)


def test_ensure_max_map_count_on_windows_sets_docker_desktop_vm():
    calls, values = [], iter(["65530", "262144"])

    def run(cmd, **kwargs):
        calls.append(cmd)
        out = next(values) if cmd[-1] == "/proc/sys/vm/max_map_count" else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    deploy.ensure_max_map_count(run=run, log=lambda m: None, platform="win32")
    assert ["wsl", "-d", "docker-desktop", "sysctl", "-w", "vm.max_map_count=262144"] in calls
