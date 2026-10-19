"""Per-source telemetry checks: did each expected source deliver alert-level events recently, per agent?"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .clients import Indexer, ServiceError, WazuhApi
from .health import FAIL, NOT_VERIFIED, PASS, WARNING, CheckResult, parse_timestamp

SOURCE_ID = re.compile(r"^[a-z0-9-]{1,64}$")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class TelemetryError(ValueError):
    pass


def sources_file(root: Path) -> Path:
    return root / "deployment" / "wazuh" / "telemetry-sources.yml"


def load_sources(root: Path) -> list[dict[str, Any]]:
    path = sources_file(root)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise TelemetryError(f"{path.name}: invalid YAML: {exc}") from exc
    sources = (data or {}).get("sources") if isinstance(data, dict) else None
    if not isinstance(sources, list) or not sources:
        raise TelemetryError(f"{path.name}: needs a non-empty 'sources' list")
    seen: set[str] = set()
    for s in sources:
        sid = str(s.get("id", "")) if isinstance(s, dict) else ""
        if not SOURCE_ID.match(sid) or sid in seen:
            raise TelemetryError(f"{path.name}: source id {sid!r} is invalid or duplicated")
        seen.add(sid)
        groups = s.get("rule_groups")
        if not NAME.match(str(s.get("agent_group", ""))) or not s.get("description"):
            raise TelemetryError(f"{sid}: needs agent_group and description")
        if not isinstance(groups, list) or not groups or not all(isinstance(g, str) and NAME.match(g) for g in groups):
            raise TelemetryError(f"{sid}: rule_groups must be a non-empty list of rule group names")
        hours = s.get("max_silence_hours")
        if not isinstance(hours, int) or not 1 <= hours <= 8760:
            raise TelemetryError(f"{sid}: max_silence_hours must be an integer in 1..8760")
    return sources


def latest_event(indexer: Indexer, agent_id: str, rule_groups: list[str], since: datetime) -> str | None:
    body = {"size": 1, "sort": [{"timestamp": {"order": "desc"}}], "_source": ["timestamp"],
            "query": {"bool": {"filter": [{"term": {"agent.id": agent_id}}, {"terms": {"rule.groups": rule_groups}},
                                          {"range": {"timestamp": {"gte": since.isoformat()}}}]}}}
    try:
        hits = indexer.request("POST", "/wazuh-alerts-*/_search", json=body)["hits"]["hits"]
    except ServiceError as exc:
        if exc.status_code == 404:
            return None
        raise
    return hits[0]["_source"]["timestamp"] if hits else None


def check_sources(api: WazuhApi, indexer: Indexer, sources: list[dict[str, Any]], now: datetime) -> list[CheckResult]:
    agents = [a for a in api.affected_items("/agents", {"select": "id,name,status,group", "limit": 500})
              if a.get("id") != "000"]
    results: list[CheckResult] = []
    for s in sources:
        members = [a for a in agents if s["agent_group"] in (a.get("group") or [])]
        if not members:
            results.append(CheckResult(s["id"], NOT_VERIFIED, f"no agent in group {s['agent_group']!r}; source not deployed"))
            continue
        for agent in members:
            name = f"{s['id']}@{agent.get('name')}"
            if agent.get("status") != "active":
                results.append(CheckResult(name, WARNING, f"agent is {agent.get('status')}; the source cannot deliver events",
                                           {"agent_status": agent.get("status")}))
                continue
            try:
                latest = latest_event(indexer, agent["id"], s["rule_groups"], now - timedelta(hours=s["max_silence_hours"]))
            except ServiceError as exc:
                results.append(CheckResult(name, FAIL, str(exc), {"http_status": exc.status_code}))
                continue
            if latest is None:
                results.append(CheckResult(name, WARNING, f"no alert-level events ({s['description']}) in "
                                                          f"{s['max_silence_hours']} h: broken or quiet, not proof of either"))
            else:
                age = round((now - parse_timestamp(latest)).total_seconds() / 3600, 1)
                results.append(CheckResult(name, PASS, f"latest {s['description']} event {age} h ago", {"latest": latest}))
    return results
