"""Backup/restore logic tests. Docker is replaced by a recorder; no containers or volumes are touched."""
import json
import subprocess
from pathlib import Path

import pytest

from aegissoc import backup
from aegissoc.backup import RESTORE_PROJECT, BackupError, restore_volume_name, sha256_file, verify_archives


def test_restore_volume_names_are_isolated():
    assert restore_volume_name("aegissoc_wazuh-indexer-data", "aegissoc") == f"{RESTORE_PROJECT}_wazuh-indexer-data"
    with pytest.raises(BackupError):
        restore_volume_name("other_wazuh_etc", "aegissoc")


def test_verify_archives_detects_missing_and_modified(tmp_path):
    (tmp_path / "a.tar.gz").write_bytes(b"data")
    manifest = {"volumes": {"v1": {"file": "a.tar.gz", "sha256": sha256_file(tmp_path / "a.tar.gz")},
                            "v2": {"file": "missing.tar.gz", "sha256": "0" * 64}},
                "files": {"env": {"file": "a.tar.gz", "sha256": "f" * 64}}}
    problems = verify_archives(tmp_path, manifest)
    assert any("missing" in p for p in problems) and any("mismatch" in p for p in problems)
    assert not any(p.startswith("volumes/v1") for p in problems)


def test_latest_backup_skips_incomplete_folders(ctx):
    with pytest.raises(BackupError, match="no complete backup"):
        backup.latest_backup(ctx)
    root = backup.backup_root(ctx)
    for name, complete in (("aegissoc-backup-20261001T000000Z", True), ("aegissoc-backup-20261002T000000Z", False)):
        (root / name).mkdir(parents=True)
        if complete:
            (root / name / "manifest.json").write_text("{}")
    assert backup.latest_backup(ctx).name == "aegissoc-backup-20261001T000000Z"


def test_compose_down_refused_for_live_project(ctx):
    with pytest.raises(BackupError, match="restore project"):
        backup._compose(ctx, ctx.lock.compose_project, "down", "--volumes", run=lambda *a, **k: None)


def test_compose_down_allowed_for_restore_project(ctx):
    calls = []
    backup._compose(ctx, RESTORE_PROJECT, "down", "--volumes", run=lambda cmd, **kw: calls.append(cmd))
    assert calls[0][calls[0].index("-p") + 1] == RESTORE_PROJECT


def test_verify_restore_never_touches_live_volumes_and_restarts_live(ctx, tmp_path, monkeypatch):
    folder = tmp_path / "aegissoc-backup-x"
    (folder / "volumes").mkdir(parents=True)
    (folder / "volumes" / "aegissoc_wazuh_etc.tar.gz").write_bytes(b"x")
    manifest = {"created_at": "t", "project": "aegissoc", "images": {"manager": "img@sha256:1"},
                "snapshot": {"alert_count": 5, "agents": ["lnx"], "aegissoc_rules": [100100]},
                "volumes": {"aegissoc_wazuh_etc": {"file": "volumes/aegissoc_wazuh_etc.tar.gz",
                                                   "sha256": sha256_file(folder / "volumes" / "aegissoc_wazuh_etc.tar.gz")}},
                "files": {}}
    (folder / "manifest.json").write_text(json.dumps(manifest))
    monkeypatch.setattr(backup.time, "sleep", lambda s: None)

    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    checks = lambda: {"alert_count": 6, "agents": ["lnx"], "rules_loaded": [100100], "retention_policy": "p"}  # noqa: E731
    result = backup.verify_restore(ctx, folder, checks=checks, live_ready=lambda: True, run=run, log=lambda m: None)
    assert result["status"] == "PASSED" and result["live_stack_healthy_after"] is True

    flat = [" ".join(c) for c in calls]
    assert not any("volume rm aegissoc_" in c for c in flat), "live volumes must never be removed"
    assert any("-xzf" in c and f"{RESTORE_PROJECT}_wazuh_etc:/dst" in c for c in flat)
    downs = [c for c in calls if "down" in c]
    assert downs and all(c[c.index("-p") + 1] == RESTORE_PROJECT for c in downs)
    assert any(c[c.index("-p") + 1] == "aegissoc" and c[-1] == "start" for c in calls if "-p" in c)


def test_verify_restore_fails_when_alerts_missing(ctx, tmp_path, monkeypatch):
    folder = tmp_path / "b"
    folder.mkdir()
    (folder / "manifest.json").write_text(json.dumps({
        "created_at": "t", "project": "aegissoc", "images": {"manager": "i"}, "files": {}, "volumes": {},
        "snapshot": {"alert_count": 100, "agents": [], "aegissoc_rules": []}}))
    monkeypatch.setattr(backup.time, "sleep", lambda s: None)
    ok = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", "")  # noqa: E731
    checks = lambda: {"alert_count": 10, "agents": [], "rules_loaded": [1], "retention_policy": "p"}  # noqa: E731
    result = backup.verify_restore(ctx, folder, checks=checks, live_ready=lambda: True, run=ok, log=lambda m: None, timeout=0.5)
    assert result["status"] == "FAILED" and result["checks"]["alerts_restored"] is False


def test_verify_restore_waits_for_full_alert_recovery(ctx, tmp_path, monkeypatch):
    # Regression: the first partial count (38 of 664) ended the wait and produced a misleading FAIL.
    folder = tmp_path / "d"
    folder.mkdir()
    (folder / "manifest.json").write_text(json.dumps({
        "created_at": "t", "project": "aegissoc", "images": {"manager": "i"}, "files": {}, "volumes": {},
        "snapshot": {"alert_count": 664, "agents": ["lnx"], "aegissoc_rules": [100100]}}))
    monkeypatch.setattr(backup.time, "sleep", lambda s: None)
    counts = iter([38, 300, 664])
    checks = lambda: {"alert_count": next(counts, 664), "agents": ["lnx"], "rules_loaded": [100100], "retention_policy": "p"}  # noqa: E731
    ok = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, "", "")  # noqa: E731
    result = backup.verify_restore(ctx, folder, checks=checks, live_ready=lambda: True, run=ok, log=lambda m: None)
    assert result["status"] == "PASSED" and result["observed"]["alert_count"] == 664


def test_tampered_backup_is_refused_before_stopping_live(ctx, tmp_path):
    folder = tmp_path / "c"
    (folder / "volumes").mkdir(parents=True)
    (folder / "volumes" / "v.tar.gz").write_bytes(b"x")
    (folder / "manifest.json").write_text(json.dumps({
        "created_at": "t", "project": "aegissoc", "images": {"manager": "i"}, "files": {}, "snapshot": {},
        "volumes": {"aegissoc_v": {"file": "volumes/v.tar.gz", "sha256": "0" * 64}}}))
    calls = []
    with pytest.raises(BackupError, match="integrity"):
        backup.verify_restore(ctx, folder, checks=dict, live_ready=lambda: True, run=lambda c, **k: calls.append(c), log=lambda m: None)
    assert calls == []
