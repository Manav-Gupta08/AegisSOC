from __future__ import annotations

import hashlib
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

import yaml

from . import __version__
from .clients import Indexer, ServiceError, WazuhApi

SCENARIO_ID = re.compile(r"^(LNX|WIN|NET)-\d{3}$")
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
RUN_AS = {"root", "default"}
MAX_TIMEOUT = 600

PASSED, FAILED, TIMED_OUT, INCONCLUSIVE, SKIPPED, CLEANUP_REQUIRED = (
    "PASSED", "FAILED", "TIMED_OUT", "INCONCLUSIVE", "SKIPPED", "CLEANUP_REQUIRED")

Runner = Callable[..., subprocess.CompletedProcess]


class ScenarioError(ValueError):
    pass


def _check_command(sid: str, where: str, cmd: Any) -> None:
    if not isinstance(cmd, dict) or cmd.get("run_as") not in RUN_AS:
        raise ScenarioError(f"{sid}: {where} needs run_as in {sorted(RUN_AS)}")
    argv = cmd.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) and a for a in argv):
        raise ScenarioError(f"{sid}: {where}.argv must be a non-empty list of strings")


def validate_scenario(data: dict[str, Any], path: Path) -> dict[str, Any]:
    sid = str(data.get("id", ""))
    if not SCENARIO_ID.match(sid):
        raise ScenarioError(f"{path.name}: invalid id {sid!r}")
    if not path.name.startswith(sid):
        raise ScenarioError(f"{path.name}: file name must start with the scenario id {sid}")
    for key in ("title", "technique", "platform", "description", "target", "safety", "execute", "expected", "timeout_seconds"):
        if not data.get(key):
            raise ScenarioError(f"{sid}: missing {key}")
    if not TECHNIQUE.match(str(data["technique"])):
        raise ScenarioError(f"{sid}: invalid ATT&CK technique {data['technique']}")
    if data["platform"] != "linux":
        raise ScenarioError(f"{sid}: only platform 'linux' is supported by this runner")
    target = data["target"]
    if not target.get("agent_group") or not target.get("wsl_distro"):
        raise ScenarioError(f"{sid}: target needs agent_group and wsl_distro")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", str(target["wsl_distro"])):
        raise ScenarioError(f"{sid}: invalid wsl_distro")
    _check_command(sid, "execute", data["execute"])
    for i, cmd in enumerate(data.get("prerequisites") or []):
        _check_command(sid, f"prerequisites[{i}]", cmd)
    for i, cmd in enumerate(data.get("cleanup") or []):
        _check_command(sid, f"cleanup[{i}]", cmd)
    if data.get("cleanup"):
        if not data.get("verify_cleanup"):
            raise ScenarioError(f"{sid}: cleanup requires verify_cleanup")
        _check_command(sid, "verify_cleanup", data["verify_cleanup"])
    expected = data["expected"]
    if not (expected.get("detection_rules") or expected.get("forbidden_rules")):
        raise ScenarioError(f"{sid}: expected needs detection_rules or forbidden_rules")
    if expected.get("forbidden_rules") and not data.get("observe_full_window"):
        raise ScenarioError(f"{sid}: negative scenarios must set observe_full_window: true")
    timeout = data["timeout_seconds"]
    if not isinstance(timeout, int) or not 10 <= timeout <= MAX_TIMEOUT:
        raise ScenarioError(f"{sid}: timeout_seconds must be an integer in 10..{MAX_TIMEOUT}")
    data["_path"] = path
    return data


def load_scenarios(root: Path) -> dict[str, dict[str, Any]]:
    scenarios: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "scenarios").rglob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ScenarioError(f"{path.name}: must be a mapping")
        sc = validate_scenario(data, path)
        if sc["id"] in scenarios:
            raise ScenarioError(f"duplicate scenario id {sc['id']}")
        scenarios[sc["id"]] = sc
    return scenarios


def wsl_argv(distro: str, cmd: dict[str, Any]) -> list[str]:
    user = ["-u", "root"] if cmd["run_as"] == "root" else []
    return ["wsl", "-d", distro, *user, "--", *cmd["argv"]]


@dataclass
class ScenarioResult:
    scenario_id: str
    title: str
    technique: str
    status: str
    reason: str
    started_at: str | None = None
    finished_at: str | None = None
    agent: dict[str, Any] = field(default_factory=dict)
    execute_exit_code: int | None = None
    expected: dict[str, Any] = field(default_factory=dict)
    observed_alerts: list[dict[str, Any]] = field(default_factory=list)
    first_detection_latency_s: float | None = None
    cleanup: str = "not_required"
    scenario_sha256: str = ""


def resolve_agent(api: WazuhApi, group: str) -> tuple[dict[str, Any] | None, str]:
    agents = [a for a in api.affected_items("/agents", {"select": "id,name,status,group,version", "limit": 500})
              if group in (a.get("group") or []) and a.get("id") != "000"]
    if not agents:
        return None, f"no agent in group {group!r}"
    if len(agents) > 1:
        return None, f"ambiguous target: {len(agents)} agents in group {group!r}"
    agent = agents[0]
    if agent.get("status") != "active":
        return None, f"agent {agent.get('name')} is {agent.get('status')}"
    return agent, ""


def query_alerts(indexer: Indexer, agent_id: str, since: datetime, rule_ids: list[str] | None = None,
                 rule_groups: list[str] | None = None) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = [
        {"term": {"agent.id": agent_id}},
        {"range": {"timestamp": {"gte": since.isoformat()}}},
    ]
    if rule_ids:
        filters.append({"terms": {"rule.id": rule_ids}})
    if rule_groups:
        filters.append({"terms": {"rule.groups": rule_groups}})
    body = {"size": 200, "sort": [{"timestamp": "asc"}], "query": {"bool": {"filter": filters}},
            "_source": ["timestamp", "rule.id", "rule.level", "rule.description", "syscheck.path", "syscheck.event"]}
    try:
        hits = indexer.request("POST", "/wazuh-alerts-*/_search", json=body)["hits"]["hits"]
    except ServiceError as exc:
        if exc.status_code == 404:
            return []
        raise
    return [{"timestamp": h["_source"]["timestamp"], "rule_id": str(h["_source"]["rule"]["id"]),
             "level": h["_source"]["rule"].get("level"),
             "path": (h["_source"].get("syscheck") or {}).get("path")} for h in hits]


def classify(expected: dict[str, Any], observed_ids: set[str], agent_had_alerts: bool) -> tuple[str, str]:
    """Outcome from observed alerts only; the simulation's exit code is never considered."""
    want = {str(r) for r in expected.get("detection_rules") or []}
    forbidden = {str(r) for r in expected.get("forbidden_rules") or []}
    telemetry = {str(r) for r in expected.get("telemetry_rules") or []}
    telemetry_seen = not telemetry or bool(telemetry & observed_ids)

    if forbidden & observed_ids:
        return FAILED, f"forbidden rule(s) fired: {sorted(forbidden & observed_ids)}"
    missing = want - observed_ids
    if not missing:
        if not telemetry_seen:
            return INCONCLUSIVE, f"expected telemetry {sorted(telemetry)} not observed"
        return PASSED, "expected detections observed" if want else "telemetry observed; no forbidden rule fired"
    if not agent_had_alerts:
        return INCONCLUSIVE, "no alerts at all from the agent in the window; telemetry may be missing"
    if not telemetry_seen:
        return INCONCLUSIVE, f"expected telemetry {sorted(telemetry)} not observed; cannot judge detection"
    if telemetry:
        return FAILED, f"telemetry observed but detection(s) {sorted(missing)} did not fire"
    return TIMED_OUT, f"detection(s) {sorted(missing)} not observed within timeout"


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Clock:
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)
    sleep: Callable[[float], None] = time.sleep


def run_scenario(sc: dict[str, Any], api: WazuhApi, indexer: Indexer, run: Runner = subprocess.run,
                 clock: Clock = Clock(), poll_seconds: float = 5.0, log: Callable[[str], None] = print) -> ScenarioResult:
    distro = sc["target"]["wsl_distro"]
    result = ScenarioResult(sc["id"], sc["title"], sc["technique"], SKIPPED, "", expected=sc["expected"],
                            scenario_sha256=hashlib.sha256(Path(sc["_path"]).read_bytes()).hexdigest())

    agent, why = resolve_agent(api, sc["target"]["agent_group"])
    if agent is None:
        result.reason = why
        return result
    result.agent = {k: agent.get(k) for k in ("id", "name", "version")}

    for pre in sc.get("prerequisites") or []:
        if run(wsl_argv(distro, pre), capture_output=True, text=True, timeout=60).returncode != 0:
            result.reason = f"prerequisite failed: {pre.get('name', pre['argv'])}"
            return result

    quiet = sc.get("quiet_before")
    if quiet:
        window = timedelta(seconds=int(quiet["seconds"]))
        recent = query_alerts(indexer, agent["id"], clock.now() - window, rule_groups=quiet["rule_groups"])
        if recent:
            wait = (_parse_ts(recent[-1]["timestamp"]) + window - clock.now()).total_seconds()
            if wait > 0:
                log(f"  {sc['id']}: waiting {int(wait)}s for a quiet correlation window")
                clock.sleep(wait)

    start = clock.now()
    result.started_at = start.isoformat()
    try:
        proc = run(wsl_argv(distro, sc["execute"]), capture_output=True, text=True, timeout=120)
        result.execute_exit_code = proc.returncode
        deadline = start + timedelta(seconds=sc["timeout_seconds"])
        want = {str(r) for r in sc["expected"].get("detection_rules") or []}
        query_ids = sorted(want | {str(r) for r in (sc["expected"].get("forbidden_rules") or [])}
                           | {str(r) for r in (sc["expected"].get("telemetry_rules") or [])})
        alerts: list[dict[str, Any]] = []
        while True:
            alerts = query_alerts(indexer, agent["id"], start - timedelta(seconds=1), rule_ids=query_ids)
            seen = {a["rule_id"] for a in alerts}
            if not sc.get("observe_full_window") and want and want <= seen:
                break
            if clock.now() >= deadline:
                break
            clock.sleep(poll_seconds)
        result.observed_alerts = alerts
        seen = {a["rule_id"] for a in alerts}
        agent_had_alerts = bool(seen) or bool(query_alerts(indexer, agent["id"], start - timedelta(seconds=1)))
        result.status, result.reason = classify(sc["expected"], seen, agent_had_alerts)
        firsts = [_parse_ts(a["timestamp"]) for a in alerts if a["rule_id"] in want]
        if firsts:
            result.first_detection_latency_s = round((min(firsts) - start).total_seconds(), 3)
    finally:
        if sc.get("cleanup"):
            ok = all(run(wsl_argv(distro, c), capture_output=True, text=True, timeout=60).returncode == 0 for c in sc["cleanup"])
            verified = run(wsl_argv(distro, sc["verify_cleanup"]), capture_output=True, text=True, timeout=60).returncode == 0
            result.cleanup = "verified" if ok and verified else "FAILED"
            if result.cleanup == "FAILED":
                result.reason = f"{result.status}: {result.reason}; cleanup failed - manual cleanup required"
                result.status = CLEANUP_REQUIRED
        result.finished_at = clock.now().isoformat()
    return result


def run_record(results: list[ScenarioResult], environment: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, int] = {}
    for r in results:
        summary[r.status] = summary.get(r.status, 0) + 1
    return {
        "schema_version": "1.0",
        "tool": "aegissoc.scenarios",
        "tool_version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": environment,
        "summary": summary,
        "results": [asdict(r) for r in results],
    }
