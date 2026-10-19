from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Callable

from .deploy import MAX_MAP_COUNT, read_max_map_count
from .health import FAIL, NOT_VERIFIED, PASS, WARNING, CheckResult
from .settings import DEFAULT_SETTINGS, Paths, parse_env

MIN_COMPOSE = (2, 24, 4)
MIN_DOCKER_MEM_GIB = 8
MIN_FREE_GIB = 50
GIB = 1024 ** 3


def parse_version(text: str) -> tuple[int, ...] | None:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", text)
    return tuple(int(x) for x in match.groups()) if match else None


def parse_wslconfig_memory(text: str) -> str | None:
    in_wsl2 = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line.startswith("["):
            in_wsl2 = line.lower() == "[wsl2]"
        elif in_wsl2 and "=" in line:
            key, value = (p.strip() for p in line.split("=", 1))
            if key.lower() == "memory":
                return value
    return None


def port_bindable(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def check_ports(settings: dict[str, str], bindable: Callable[[str, int], bool] = port_bindable) -> CheckResult:
    agent_bind = settings["AEGIS_AGENT_BIND"]
    wanted = [(agent_bind, 1514), (agent_bind, 1515), ("127.0.0.1", 55000), ("127.0.0.1", 9200),
              ("127.0.0.1", int(settings["AEGIS_DASHBOARD_PORT"]))]
    busy = [f"{h}:{p}" for h, p in wanted if not bindable(h, p)]
    if busy:
        return CheckResult("host_ports", WARNING,
                           f"ports in use or reserved: {busy} (expected if the AegisSOC stack is already running)", {"busy": busy})
    return CheckResult("host_ports", PASS, "all stack ports available")


def run_preflight(paths: Paths, run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[CheckResult]:
    results: list[CheckResult] = []

    py = sys.version_info
    results.append(CheckResult("python", PASS if py >= (3, 11) else FAIL, f"Python {py.major}.{py.minor}.{py.micro}"))

    if shutil.which("docker") is None:
        return results + [CheckResult("docker_cli", FAIL, "docker not found on PATH")]

    info = run(["docker", "info", "--format", "{{.ServerVersion}}|{{.MemTotal}}|{{.NCPU}}"], capture_output=True, text=True)
    daemon_up = info.returncode == 0
    if not daemon_up:
        results.append(CheckResult("docker_daemon", FAIL, "Docker daemon not reachable; start Docker Desktop"))
    else:
        server, mem, ncpu = info.stdout.strip().split("|")
        mem_gib = round(int(mem) / GIB, 1)
        results.append(CheckResult("docker_daemon", PASS, f"Docker Engine {server}"))
        results.append(CheckResult(
            "docker_resources", PASS if mem_gib >= MIN_DOCKER_MEM_GIB else WARNING,
            f"{mem_gib} GiB RAM, {ncpu} CPUs visible to Docker (Wazuh single-node needs >= {MIN_DOCKER_MEM_GIB} GiB)",
            {"mem_gib": mem_gib, "cpus": int(ncpu)}))

    compose = run(["docker", "compose", "version", "--short"], capture_output=True, text=True)
    version = parse_version(compose.stdout) if compose.returncode == 0 else None
    if version is None:
        results.append(CheckResult("compose", FAIL, "docker compose not available"))
    else:
        ok = version >= MIN_COMPOSE
        results.append(CheckResult("compose", PASS if ok else FAIL,
                                   f"Compose {'.'.join(map(str, version))} (need >= {'.'.join(map(str, MIN_COMPOSE))} for !override)"))

    free_gib = round(shutil.disk_usage(paths.root).free / GIB, 1)
    results.append(CheckResult("repo_disk", PASS if free_gib >= MIN_FREE_GIB else WARNING, f"{free_gib} GiB free on repository drive"))

    settings = dict(DEFAULT_SETTINGS)
    if paths.env_file.is_file():
        settings.update(parse_env(paths.env_file.read_text(encoding="utf-8")))
    results.append(check_ports(settings))

    local = os.environ.get("LOCALAPPDATA")
    if local:
        vhdx = Path(local) / "Docker" / "wsl" / "disk" / "docker_data.vhdx"
        if vhdx.is_file():
            free = round(shutil.disk_usage(vhdx.anchor).free / GIB, 1)
            results.append(CheckResult(
                "docker_disk_image", PASS if free >= MIN_FREE_GIB else WARNING,
                f"Docker disk image on {vhdx.anchor} ({round(vhdx.stat().st_size / GIB, 1)} GiB); {free} GiB free there. "
                "Move it via Docker Desktop > Settings > Resources > Disk image location if space is low.",
                {"drive_free_gib": free}))

    if sys.platform == "win32":
        current = read_max_map_count(run) if daemon_up else None
        if current is None:
            results.append(CheckResult("vm_max_map_count", NOT_VERIFIED, "could not read (Docker Desktop not running?)"))
        else:
            results.append(CheckResult("vm_max_map_count", PASS if current >= MAX_MAP_COUNT else WARNING,
                                       f"{current} (need >= {MAX_MAP_COUNT}; `aegis up` sets it)"))

        wslconfig = Path.home() / ".wslconfig"
        memory = parse_wslconfig_memory(wslconfig.read_text(encoding="utf-8")) if wslconfig.is_file() else None
        results.append(CheckResult(
            "wsl_memory_cap", PASS if memory else WARNING,
            f"[wsl2] memory={memory}" if memory else "no WSL2 memory cap; see deployment/wsl/wslconfig.example"))

    return results
