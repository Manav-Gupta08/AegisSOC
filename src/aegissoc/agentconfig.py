from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .clients import WazuhApi
from .settings import Paths

GROUP_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# Elements valid at the top level of a Wazuh centralized agent.conf that AegisSOC uses.
ALLOWED_SECTIONS = {"localfile", "syscheck", "rootcheck", "sca", "wodle", "labels", "client_buffer"}


class AgentConfigError(ValueError):
    pass


@dataclass(frozen=True)
class GroupConfig:
    name: str
    path: Path
    xml: str


def groups_dir(paths: Paths) -> Path:
    return paths.root / "deployment" / "wazuh" / "agent-groups"


def validate_group_config(name: str, text: str) -> None:
    if not GROUP_NAME.match(name):
        raise AgentConfigError(f"invalid group name {name!r}")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise AgentConfigError(f"{name}: agent.conf is not well-formed XML: {exc}") from exc
    if root.tag != "agent_config":
        raise AgentConfigError(f"{name}: root element must be <agent_config>, got <{root.tag}>")
    unknown = sorted({child.tag for child in root} - ALLOWED_SECTIONS)
    if unknown:
        raise AgentConfigError(f"{name}: unsupported sections {unknown}")
    for lf in root.iter("localfile"):
        if not (lf.findtext("location") or "").strip() or not (lf.findtext("log_format") or "").strip():
            raise AgentConfigError(f"{name}: every <localfile> needs <location> and <log_format>")


def load_group_configs(paths: Paths) -> list[GroupConfig]:
    base = groups_dir(paths)
    configs = []
    for conf in sorted(base.glob("*/agent.conf")):
        text = conf.read_text(encoding="utf-8")
        validate_group_config(conf.parent.name, text)
        configs.append(GroupConfig(conf.parent.name, conf, text))
    if not configs:
        raise AgentConfigError(f"no agent.conf files under {base}")
    return configs


def group_for_platform(platform: str | None) -> str | None:
    if not platform:
        return None
    return "windows" if platform.lower() == "windows" else "linux"


def assign_group(api: WazuhApi, agent_name: str, group: str, known_groups: set[str]) -> str:
    """Add one agent to an additional group; returns the agent id. Agents keep their OS group."""
    if group not in known_groups:
        raise AgentConfigError(f"unknown group {group!r}; known: {sorted(known_groups)}")
    matches = [a for a in api.affected_items("/agents", {"select": "id,name,group", "limit": 500})
               if a.get("name") == agent_name and a.get("id") != "000"]
    if len(matches) != 1:
        raise AgentConfigError(f"expected exactly one agent named {agent_name!r}, found {len(matches)}")
    agent = matches[0]
    if group not in (agent.get("group") or []):
        api.request("PUT", f"/agents/{agent['id']}/group/{group}")
    return agent["id"]


def apply_group_configs(api: WazuhApi, configs: list[GroupConfig], log: Callable[[str], None] = print) -> dict[str, Any]:
    existing = {g["name"] for g in api.affected_items("/groups", {"limit": 500})}
    names = {c.name for c in configs}
    for cfg in configs:
        if cfg.name not in existing:
            api.request("POST", "/groups", json={"group_id": cfg.name})
            log(f"created group {cfg.name}")
        api.request("PUT", f"/groups/{cfg.name}/configuration", data=cfg.xml.encode("utf-8"),
                    headers={"Content-Type": "application/xml"})
        log(f"uploaded {cfg.path.as_posix()} -> group {cfg.name}")

    assigned: dict[str, str] = {}
    agents = api.affected_items("/agents", {"select": "id,name,os.platform,group", "limit": 500})
    for agent in agents:
        if agent.get("id") == "000":
            continue
        target = group_for_platform((agent.get("os") or {}).get("platform"))
        if target in names and target not in (agent.get("group") or []):
            api.request("PUT", f"/agents/{agent['id']}/group/{target}")
            assigned[agent["name"]] = target
            log(f"assigned agent {agent['name']} -> {target}")
    return {"groups": sorted(names), "assigned": assigned}
