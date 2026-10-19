from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .clients import Indexer, ServiceError, WazuhApi
from .deploy import compose_command, compose_env
from .provision import READER_API_USER, READER_INDEXER_USER, api_client, indexer_client
from .redact import redact
from .settings import Context

PASS, WARNING, FAIL, NOT_VERIFIED = "PASS", "WARNING", "FAIL", "NOT_VERIFIED"
_SEVERITY = {PASS: 0, WARNING: 1, NOT_VERIFIED: 1, FAIL: 2}

EXPECTED_SERVICES = ("wazuh.manager", "wazuh.indexer", "wazuh.dashboard")
AGENT_PORTS = {1514, 1515}
REQUIRED_DAEMONS = (
    "wazuh-analysisd", "wazuh-remoted", "wazuh-authd", "wazuh-db",
    "wazuh-modulesd", "wazuh-execd", "wazuh-logcollector", "wazuh-syscheckd",
    "wazuh-monitord", "wazuh-apid",
)
# Upstream defaults that must stop working once the stack is hardened.
DEFAULT_API_CREDENTIALS = (("wazuh", "wazuh"), ("wazuh-wui", "MyS3cr37P450r.*-"))
DEFAULT_INDEXER_CREDENTIALS = (
    ("admin", "SecretPassword"), ("admin", "admin"), ("kibanaserver", "kibanaserver"),
    ("kibanaro", "kibanaro"), ("logstash", "logstash"), ("readall", "readall"), ("snapshotrestore", "snapshotrestore"),
)


@dataclass
class CheckResult:
    name: str
    status: str
    detail: str
    observed: dict[str, Any] = field(default_factory=dict)


def overall_status(results: list[CheckResult]) -> str:
    worst = max((_SEVERITY[r.status] for r in results), default=_SEVERITY[NOT_VERIFIED])
    return {0: PASS, 1: WARNING, 2: FAIL}[worst]


def parse_compose_ps(output: str) -> list[dict[str, Any]]:
    text = output.strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def check_containers(rows: list[dict[str, Any]]) -> CheckResult:
    by_service = {r.get("Service"): r for r in rows}
    observed = {s: {"state": by_service[s].get("State"), "health": by_service[s].get("Health", "")}
                for s in EXPECTED_SERVICES if s in by_service}
    missing = [s for s in EXPECTED_SERVICES if s not in by_service]
    not_running = [s for s, o in observed.items() if o["state"] != "running"]
    unhealthy = [s for s, o in observed.items() if o["health"] == "unhealthy"]
    if missing or not_running or unhealthy:
        return CheckResult("containers", FAIL,
                           f"missing={missing} not_running={not_running} unhealthy={unhealthy}", observed)
    return CheckResult("containers", PASS, "all stack containers running", observed)


def check_port_exposure(rows: list[dict[str, Any]], agent_bind: str) -> CheckResult:
    exposed: list[str] = []
    bindings: list[str] = []
    for row in rows:
        for pub in row.get("Publishers") or []:
            port = int(pub.get("PublishedPort") or 0)
            if not port:
                continue
            url = pub.get("URL", "")
            bindings.append(f"{row.get('Service')}:{url}:{port}")
            allowed = {"127.0.0.1"} | ({agent_bind} if pub.get("TargetPort") in AGENT_PORTS else set())
            if url not in allowed:
                exposed.append(f"{row.get('Service')} {url}:{port}")
    if exposed:
        return CheckResult("port_exposure", FAIL, f"ports published beyond allowed addresses: {exposed}", {"bindings": bindings})
    if not bindings:
        return CheckResult("port_exposure", NOT_VERIFIED, "no published ports observed", {})
    return CheckResult("port_exposure", PASS, "all published ports bound to allowed addresses", {"bindings": bindings})


def check_manager_daemons(api: WazuhApi) -> CheckResult:
    status = api.affected_items("/manager/status")[0]
    down = [d for d in REQUIRED_DAEMONS if status.get(d) != "running"]
    observed = {d: status.get(d, "absent") for d in REQUIRED_DAEMONS}
    if down:
        return CheckResult("manager_daemons", FAIL, f"required daemons not running: {down}", observed)
    return CheckResult("manager_daemons", PASS, "required daemons running", observed)


def check_agents(api: WazuhApi) -> CheckResult:
    items = api.affected_items("/agents", {"select": "id,name,status,lastKeepAlive,version,group,group_config_status", "limit": 500})
    agents = [a for a in items if a.get("id") != "000"]
    observed = {a.get("name", a.get("id")): a.get("status") for a in agents}
    if not agents:
        return CheckResult("agents", WARNING, "no agents enrolled; endpoint telemetry is absent", observed)
    inactive = [n for n, s in observed.items() if s != "active"]
    if inactive:
        return CheckResult("agents", WARNING, f"agents not active (telemetry missing, not 'quiet'): {inactive}", observed)
    drift = [a.get("name") for a in agents if a.get("group_config_status", "synced") != "synced"]
    if drift:
        return CheckResult("agents", WARNING, f"agent group config not synced (drift): {drift}", observed)
    return CheckResult("agents", PASS, f"{len(agents)} agent(s) active, configs synced", observed)


def check_indexer_cluster(indexer: Indexer) -> CheckResult:
    health = indexer.request("GET", "/_cluster/health")
    status = health.get("status")
    observed = {k: health.get(k) for k in ("status", "number_of_nodes", "unassigned_shards", "active_shards_percent_as_number")}
    mapping = {"green": PASS, "yellow": WARNING, "red": FAIL}
    return CheckResult("indexer_cluster", mapping.get(status, FAIL), f"cluster status {status}", observed)


def check_indexer_disk(indexer: Indexer, warn: int, fail: int) -> CheckResult:
    rows = indexer.request("GET", "/_cat/allocation", params={"format": "json"})
    percents = {r.get("node", "?"): int(r["disk.percent"]) for r in rows if r.get("disk.percent") not in (None, "")}
    if not percents:
        return CheckResult("indexer_disk", NOT_VERIFIED, "indexer reported no disk usage", {})
    worst = max(percents.values())
    status = FAIL if worst >= fail else WARNING if worst >= warn else PASS
    return CheckResult("indexer_disk", status, f"max disk usage {worst}% (warn {warn}%, fail {fail}%)", {"disk_percent": percents})


def parse_timestamp(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def check_alert_freshness(indexer: Indexer, stale_minutes: int, now: datetime) -> CheckResult:
    body = {"size": 1, "sort": [{"timestamp": {"order": "desc"}}], "_source": ["timestamp", "agent.name", "rule.id"]}
    try:
        result = indexer.request("POST", "/wazuh-alerts-*/_search", json=body)
    except ServiceError as exc:
        if exc.status_code == 404:
            return CheckResult("alert_freshness", WARNING, "no wazuh-alerts index exists yet", {})
        raise
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return CheckResult("alert_freshness", WARNING, "no alerts indexed; pipeline unverified", {})
    latest = parse_timestamp(hits[0]["_source"]["timestamp"])
    age_min = round((now - latest).total_seconds() / 60, 1)
    observed = {"latest_alert": latest.isoformat(), "age_minutes": age_min}
    if age_min > stale_minutes:
        return CheckResult("alert_freshness", WARNING,
                           f"latest alert is {age_min} min old (> {stale_minutes}); pipeline may be stalled or lab is quiet",
                           observed)
    return CheckResult("alert_freshness", PASS, f"latest alert {age_min} min old", observed)


def check_default_credentials(api_attempt: Callable[[str, str], bool], indexer_attempt: Callable[[str, str], bool]) -> CheckResult:
    working = [f"api:{u}" for u, p in DEFAULT_API_CREDENTIALS if api_attempt(u, p)]
    working += [f"indexer:{u}" for u, p in DEFAULT_INDEXER_CREDENTIALS if indexer_attempt(u, p)]
    if working:
        return CheckResult("default_credentials", FAIL, f"default credentials still accepted: {working}", {"accepted": working})
    return CheckResult("default_credentials", PASS, "no upstream default credentials accepted", {})


def _guard(name: str, fn: Callable[[], CheckResult]) -> CheckResult:
    try:
        return fn()
    except ServiceError as exc:
        return CheckResult(name, FAIL, str(exc), {"http_status": exc.status_code})
    except (OSError, ValueError, KeyError) as exc:
        return CheckResult(name, FAIL, f"{type(exc).__name__}: {exc}", {})


def run_health(ctx: Context, run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
               credential_test: bool = False) -> list[CheckResult]:
    """credential_test performs failed logins; keep it out of polling loops (Wazuh API locks out after 50/5 min)."""
    results: list[CheckResult] = []

    ps = run(compose_command(ctx, "ps", "-a", "--format", "json"), env=compose_env(ctx), capture_output=True, text=True)
    if ps.returncode != 0:
        results.append(CheckResult("containers", FAIL, f"docker compose ps failed: {ps.stderr.strip()[:300]}"))
        rows: list[dict[str, Any]] = []
    else:
        rows = parse_compose_ps(ps.stdout)
        results.append(check_containers(rows))
    results.append(check_port_exposure(rows, ctx.env.get("AEGIS_AGENT_BIND", "127.0.0.1")))

    api = api_client(ctx)

    def api_auth() -> CheckResult:
        api.authenticate(READER_API_USER, ctx.secret("WAZUH_API_READER_PASSWORD"))
        return CheckResult("api_auth", PASS, f"authenticated as {READER_API_USER}")

    auth = _guard("api_auth", api_auth)
    results.append(auth)
    if auth.status == PASS:
        results.append(_guard("manager_daemons", lambda: check_manager_daemons(api)))
        results.append(_guard("agents", lambda: check_agents(api)))
    else:
        results += [CheckResult(n, NOT_VERIFIED, "API authentication failed") for n in ("manager_daemons", "agents")]

    indexer = indexer_client(ctx, READER_INDEXER_USER, ctx.secret("INDEXER_READER_PASSWORD"))
    results.append(_guard("indexer_cluster", lambda: check_indexer_cluster(indexer)))
    results.append(_guard("indexer_disk", lambda: check_indexer_disk(
        indexer, ctx.int_setting("AEGIS_DISK_WARN_PERCENT"), ctx.int_setting("AEGIS_DISK_FAIL_PERCENT"))))
    results.append(_guard("alert_freshness", lambda: check_alert_freshness(
        indexer, ctx.int_setting("AEGIS_ALERT_STALE_MINUTES"), datetime.now(timezone.utc))))

    def api_attempt(user: str, password: str) -> bool:
        try:
            api_client(ctx).authenticate(user, password)
            return True
        except ServiceError:
            return False

    def indexer_attempt(user: str, password: str) -> bool:
        try:
            indexer_client(ctx, user, password).request("GET", "/")
            return True
        except ServiceError:
            return False

    if credential_test:
        results.append(_guard("default_credentials", lambda: check_default_credentials(api_attempt, indexer_attempt)))
    return results


def build_report(ctx: Context, results: list[CheckResult], generated_at: datetime) -> dict[str, Any]:
    report = {
        "schema_version": "1.0",
        "tool": "aegissoc.health",
        "tool_version": __version__,
        "wazuh_version": ctx.lock.wazuh_version,
        "generated_at": generated_at.isoformat(),
        "overall": overall_status(results),
        "checks": [asdict(r) for r in results],
    }
    return redact(report, ctx.secrets())


def write_report(report: dict[str, Any], reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = report["generated_at"].replace(":", "").replace("-", "").split(".")[0]
    path = reports_dir / f"health-{stamp}.json"
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return path
