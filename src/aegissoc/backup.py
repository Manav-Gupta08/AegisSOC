"""Cold backup and restore verification. Live stack data is never modified by restore verification."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .clients import ServiceError
from .deploy import compose_command, compose_env
from .settings import Context

RESTORE_PROJECT = "aegissoc-restore"
# Restored stack listens for agents on a different loopback address so live agents never connect to it.
RESTORE_AGENT_BIND = "127.0.0.2"
Runner = Callable[..., subprocess.CompletedProcess]


class BackupError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def backup_root(ctx: Context) -> Path:
    return Path(ctx.env.get("AEGIS_BACKUP_DIR") or ctx.paths.root / "backups")


def latest_backup(ctx: Context) -> Path:
    folders = sorted(p for p in backup_root(ctx).glob("aegissoc-backup-*") if (p / "manifest.json").is_file())
    if not folders:
        raise BackupError(f"no complete backup (with manifest.json) in {backup_root(ctx)}; run `aegis backup create`")
    return folders[-1]


def stack_volumes(project: str, run: Runner) -> list[str]:
    out = run(["docker", "volume", "ls", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{.Name}}"],
              capture_output=True, text=True, check=True)
    return sorted(v for v in out.stdout.split() if v)


def restore_volume_name(source: str, source_project: str) -> str:
    prefix = f"{source_project}_"
    if not source.startswith(prefix):
        raise BackupError(f"volume {source} does not belong to project {source_project}")
    return f"{RESTORE_PROJECT}_{source[len(prefix):]}"


def _docker_path(path: Path) -> str:
    return path.resolve().as_posix()


def verify_archives(folder: Path, manifest: dict[str, Any]) -> list[str]:
    problems = []
    for section in ("volumes", "files"):
        for name, meta in manifest[section].items():
            path = folder / meta["file"]
            if not path.is_file():
                problems.append(f"{section}/{name}: missing {meta['file']}")
            elif sha256_file(path) != meta["sha256"]:
                problems.append(f"{section}/{name}: SHA-256 mismatch")
    return problems


def _compose(ctx: Context, project: str, *args: str, env_extra: dict[str, str] | None = None,
             run: Runner = subprocess.run, check: bool = True) -> subprocess.CompletedProcess:
    cmd = compose_command(ctx, *args)
    cmd[cmd.index("-p") + 1] = project
    if "down" in args and project != RESTORE_PROJECT:
        raise BackupError("refusing compose down outside the restore project")
    return run(cmd, env={**compose_env(ctx), **(env_extra or {})}, check=check, capture_output=True, text=True)


def create(ctx: Context, snapshot: dict[str, Any], run: Runner = subprocess.run, log: Callable[[str], None] = print) -> Path:
    project = ctx.lock.compose_project
    image = ctx.lock.images["manager"]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = backup_root(ctx) / f"aegissoc-backup-{stamp}"
    (folder / "volumes").mkdir(parents=True)
    (folder / "files").mkdir()
    # The backup holds .env and private keys; owner-only on POSIX hosts.
    os.chmod(folder, 0o700)

    volumes = stack_volumes(project, run)
    if not volumes:
        raise BackupError(f"no volumes found for project {project}")

    log("stopping stack for a consistent cold backup")
    stopped_at = time.monotonic()
    _compose(ctx, project, "stop", run=run)
    manifest: dict[str, Any] = {
        "schema_version": "1.0", "created_at": datetime.now(timezone.utc).isoformat(), "project": project,
        "wazuh_version": ctx.lock.wazuh_version, "images": ctx.lock.images, "snapshot": snapshot,
        "volumes": {}, "files": {},
    }
    try:
        for vol in volumes:
            target = f"volumes/{vol}.tar.gz"
            run(["docker", "run", "--rm", "--entrypoint", "tar", "-v", f"{vol}:/src:ro",
                 "-v", f"{_docker_path(folder / 'volumes')}:/dst", image, "-czf", f"/dst/{vol}.tar.gz", "-C", "/src", "."],
                check=True, capture_output=True, text=True)
            path = folder / target
            manifest["volumes"][vol] = {"file": target, "sha256": sha256_file(path), "bytes": path.stat().st_size}
            log(f"  {vol}: {path.stat().st_size} bytes")
    finally:
        log("starting stack")
        _compose(ctx, project, "start", run=run)
        manifest["downtime_seconds"] = round(time.monotonic() - stopped_at, 1)

    config_files = {
        "env": ctx.paths.env_file,
        "stack.lock.json": ctx.paths.lock_file,
        "runtime": ctx.paths.runtime_dir,
        "certs": ctx.paths.certs_dir(ctx.lock),
    }
    for name, src in config_files.items():
        archive = shutil.make_archive(str(folder / "files" / name), "zip", root_dir=src.parent if src.is_file() else src,
                                      base_dir=src.name if src.is_file() else ".")
        path = Path(archive)
        manifest["files"][name] = {"file": path.relative_to(folder).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size}

    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return folder


def _wait(predicate: Callable[[], bool], timeout: float, interval: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return True
        except (ServiceError, OSError, KeyError, ValueError):
            pass
        time.sleep(interval)
    return False


def remove_restore_project(ctx: Context, run: Runner) -> None:
    _compose(ctx, RESTORE_PROJECT, "down", "--volumes", "--remove-orphans", run=run, check=False,
             env_extra={"AEGIS_AGENT_BIND": RESTORE_AGENT_BIND})
    for vol in stack_volumes(RESTORE_PROJECT, run):
        run(["docker", "volume", "rm", vol], capture_output=True, text=True)


def verify_restore(ctx: Context, folder: Path, checks: Callable[[], dict[str, Any]], live_ready: Callable[[], bool],
                   run: Runner = subprocess.run, log: Callable[[str], None] = print, timeout: float = 900) -> dict[str, Any]:
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    problems = verify_archives(folder, manifest)
    if problems:
        raise BackupError(f"backup integrity check failed: {problems}")
    image = manifest["images"]["manager"]
    result: dict[str, Any] = {"backup": folder.name, "backup_created_at": manifest["created_at"],
                              "archives_verified": True, "started_at": datetime.now(timezone.utc).isoformat()}

    log("stopping live stack (its volumes are not touched)")
    _compose(ctx, ctx.lock.compose_project, "stop", run=run)
    t0 = time.monotonic()
    try:
        remove_restore_project(ctx, run)
        for vol, meta in manifest["volumes"].items():
            target = restore_volume_name(vol, manifest["project"])
            run(["docker", "volume", "create", "--label", f"com.docker.compose.project={RESTORE_PROJECT}",
                 "--label", f"com.docker.compose.volume={target.split('_', 1)[1]}", target], check=True, capture_output=True, text=True)
            run(["docker", "run", "--rm", "--entrypoint", "tar", "-v", f"{target}:/dst",
                 "-v", f"{_docker_path(folder / 'volumes')}:/src:ro", image, "-xzf", f"/src/{Path(meta['file']).name}", "-C", "/dst"],
                check=True, capture_output=True, text=True)
        log(f"restored {len(manifest['volumes'])} volumes into project {RESTORE_PROJECT}; starting it")
        _compose(ctx, RESTORE_PROJECT, "up", "-d", run=run, env_extra={"AEGIS_AGENT_BIND": RESTORE_AGENT_BIND})

        observed: dict[str, Any] = {}
        expected = manifest["snapshot"]

        def ready() -> bool:
            # Indices recover one by one; a partial count must not end the wait (found 2026-10-14: 38 of 664).
            observed.update(checks())
            return ((observed.get("alert_count") or 0) >= expected["alert_count"]
                    and set(expected["aegissoc_rules"]) <= set(observed.get("rules_loaded", [])))

        result["restored_stack_ready"] = _wait(ready, timeout)
        result["recovery_seconds"] = round(time.monotonic() - t0, 1)
        result["observed"] = observed
        result["checks"] = {
            "alerts_restored": (observed.get("alert_count") or 0) >= expected["alert_count"],
            "agents_restored": set(expected["agents"]) <= set(observed.get("agents", [])),
            "rules_loaded": set(expected["aegissoc_rules"]) <= set(observed.get("rules_loaded", [])),
            "retention_policy_present": bool(observed.get("retention_policy")),
        }
        result["status"] = "PASSED" if result["restored_stack_ready"] and all(result["checks"].values()) else "FAILED"
    finally:
        log("removing restore project and restarting live stack")
        remove_restore_project(ctx, run)
        _compose(ctx, ctx.lock.compose_project, "start", run=run)
        result["live_stack_healthy_after"] = _wait(live_ready, timeout)
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result
