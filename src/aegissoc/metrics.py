"""Operational and detection metrics. Definitions: docs/operations.md#metrics. Every metric reports its sample size."""
from __future__ import annotations

import json
import statistics
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from .clients import Indexer
from .reporting import md

EXECUTED = {"PASSED", "FAILED", "TIMED_OUT", "INCONCLUSIVE", "CLEANUP_REQUIRED"}


def load_reports(folders: list[Path], pattern: str) -> list[dict[str, Any]]:
    """Load JSON reports from several folders, de-duplicated by generated_at, oldest first."""
    seen: dict[str, dict[str, Any]] = {}
    for folder in folders:
        for path in folder.glob(pattern):
            data = json.loads(path.read_text(encoding="utf-8"))
            seen.setdefault(data.get("generated_at", path.name), data)
    return [seen[k] for k in sorted(seen)]


def _ts(value: str) -> datetime:
    v = value.replace("Z", "+00:00")
    if len(v) > 5 and v[-5] in "+-" and v[-3] != ":":
        v = v[:-2] + ":" + v[-2:]
    return datetime.fromisoformat(v)


def scenario_metrics(reports: list[dict[str, Any]]) -> dict[str, Any]:
    runs: dict[str, list[dict[str, Any]]] = {}
    for rep in reports:
        for r in rep.get("results", []):
            runs.setdefault(r["scenario_id"], []).append(r)
    latest = {sid: rs[-1] for sid, rs in runs.items()}
    executed = [r for r in latest.values() if r["status"] in EXECUTED]
    passed = [r for r in executed if r["status"] == "PASSED"]
    regressions = sorted(sid for sid, rs in runs.items()
                         if len(rs) >= 2 and rs[-2]["status"] == "PASSED" and rs[-1]["status"] in EXECUTED - {"PASSED"})
    with_prev = [sid for sid, rs in runs.items() if len(rs) >= 2 and rs[-2]["status"] == "PASSED"]
    latencies = [r["first_detection_latency_s"] for rs in runs.values() for r in rs
                 if r.get("first_detection_latency_s") is not None and r["status"] == "PASSED"]
    all_exec = [r for rs in runs.values() for r in rs if r["status"] in EXECUTED]
    return {
        "scenarios_known": len(runs),
        "latest_executed": len(executed),
        "latest_pass_rate": round(len(passed) / len(executed), 3) if executed else None,
        "latest_failures": sorted(r["scenario_id"] for r in executed if r["status"] != "PASSED"),
        "regressions": regressions,
        "regression_rate": round(len(regressions) / len(with_prev), 3) if with_prev else None,
        "total_runs_executed": len(all_exec),
        "cleanup_failures": sum(1 for r in all_exec if r["status"] == "CLEANUP_REQUIRED"),
        "trigger_to_alert_latency_s": {
            "samples": len(latencies),
            "median": round(statistics.median(latencies), 3) if latencies else None,
            "max": max(latencies) if latencies else None,
        },
    }


def availability_metrics(health_reports: list[dict[str, Any]]) -> dict[str, Any]:
    samples = []
    for rep in health_reports:
        agents = next((c for c in rep.get("checks", []) if c["name"] == "agents"), None)
        if agents:
            samples.append((rep["generated_at"], agents["status"] == "PASS", rep.get("overall")))
    ok = sum(1 for _, up, _ in samples if up)
    return {
        "health_samples": len(samples),
        "first_sample": samples[0][0] if samples else None,
        "last_sample": samples[-1][0] if samples else None,
        "agents_all_active_ratio": round(ok / len(samples), 3) if samples else None,
        "overall_fail_samples": sum(1 for *_, overall in samples if overall == "FAIL"),
    }


def case_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    durations = []
    for c in cases:
        closing = next((e for e in reversed(c["audit"]) if e["action"] == "transition"
                        and e["detail"]["to"] in ("closed", "false_positive")), None)
        if closing:
            durations.append((_ts(closing["at"]) - _ts(c["created_at"])).total_seconds() / 60)
    by_class: dict[str, int] = {}
    for c in cases:
        by_class[c["classification"]] = by_class.get(c["classification"], 0) + 1
    return {
        "cases": len(cases),
        "open": sum(1 for c in cases if c["status"] not in ("closed", "false_positive")),
        "closed": len(durations),
        "resolution_minutes": {"median": round(statistics.median(durations), 1) if durations else None,
                               "max": round(max(durations), 1) if durations else None},
        "by_classification": by_class,
        "analyst_labelled_false_positives": by_class.get("false_positive", 0),
    }


def alert_volume(indexer: Indexer, days: int, now: datetime) -> dict[str, Any]:
    since = (now - timedelta(days=days)).isoformat()
    body = {
        "size": 0,
        "query": {"range": {"timestamp": {"gte": since}}},
        "aggs": {
            "per_day": {"date_histogram": {"field": "timestamp", "calendar_interval": "day"}},
            "per_agent": {"terms": {"field": "agent.name", "size": 20}},
            "levels": {"range": {"field": "rule.level", "ranges": [
                {"key": "0-6 low", "to": 7}, {"key": "7-11 medium", "from": 7, "to": 12}, {"key": "12+ high", "from": 12}]}},
            "top_rules": {"terms": {"field": "rule.id", "size": 10},
                          "aggs": {"desc": {"terms": {"field": "rule.description", "size": 1}}}},
            "aegissoc_rules": {"filter": {"range": {"rule.id": {"gte": 100000, "lte": 100999}}}},
        },
    }
    r = indexer.request("POST", "/wazuh-alerts-*/_search", json=body)
    a = r["aggregations"]
    return {
        "window_days": days,
        "total": r["hits"]["total"]["value"],
        "per_day": {b["key_as_string"][:10]: b["doc_count"] for b in a["per_day"]["buckets"]},
        "per_agent": {b["key"]: b["doc_count"] for b in a["per_agent"]["buckets"]},
        "by_level": {b["key"]: b["doc_count"] for b in a["levels"]["buckets"]},
        "top_rules": [{"rule_id": b["key"], "count": b["doc_count"],
                       "description": (b["desc"]["buckets"] or [{"key": ""}])[0]["key"]} for b in a["top_rules"]["buckets"]],
        "aegissoc_rule_alerts": a["aegissoc_rules"]["doc_count"],
    }


def storage(indexer: Indexer, total_alerts_all_time: int | None) -> dict[str, Any]:
    rows = indexer.request("GET", "/_cat/allocation", params={"format": "json", "bytes": "b"})
    node = next((r for r in rows if r.get("disk.indices") not in (None, "")), {})
    used = int(node.get("disk.indices", 0)) if node else None
    return {
        "indices_bytes": used,
        "disk_percent": int(node["disk.percent"]) if node.get("disk.percent") else None,
        "disk_avail_bytes": int(node["disk.avail"]) if node.get("disk.avail") else None,
        "bytes_per_alert_upper_bound": round(used / total_alerts_all_time) if used and total_alerts_all_time else None,
    }


def parse_docker_stats(output: str) -> list[dict[str, Any]]:
    rows = []
    for line in output.strip().splitlines():
        d = json.loads(line)
        rows.append({"name": d["Name"], "cpu_percent": float(d["CPUPerc"].rstrip("%")),
                     "mem_usage": d["MemUsage"].split("/")[0].strip(), "mem_limit": d["MemUsage"].split("/")[1].strip(),
                     "mem_percent": float(d["MemPerc"].rstrip("%"))})
    return rows


def resources(project: str, run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[dict[str, Any]]:
    out = run(["docker", "stats", "--no-stream", "--format", "{{json .}}",
               *[f"{project}-wazuh.{s}-1" for s in ("manager", "indexer", "dashboard")]],
              capture_output=True, text=True, timeout=60)
    return parse_docker_stats(out.stdout) if out.returncode == 0 else []


def render_markdown(m: dict[str, Any]) -> str:
    s, v, c, st = m["scenarios"], m["alert_volume"], m["cases"], m["storage"]
    av, lat = m["availability"], m["scenarios"]["trigger_to_alert_latency_s"]
    fmt = lambda x: "n/a" if x is None else x  # noqa: E731
    lines = [
        "# AegisSOC Metrics", "",
        f"Generated {m['generated_at']}. Definitions: docs/operations.md#metrics. Lab measurements, not real-world rates.", "",
        "## Detection validation", "",
        "| Metric | Value | Sample |", "|---|---|---|",
        f"| Latest pass rate | {fmt(s['latest_pass_rate'])} | {s['latest_executed']} executed scenarios |",
        f"| Latest failures | {', '.join(s['latest_failures']) or 'none'} | |",
        f"| Regression rate | {fmt(s['regression_rate'])} | scenarios with a previous PASS |",
        f"| Trigger-to-alert latency median / max (s) | {fmt(lat['median'])} / {fmt(lat['max'])} | {lat['samples']} passing runs |",
        f"| Cleanup failures | {s['cleanup_failures']} | {s['total_runs_executed']} executed runs |", "",
        f"## Alert volume (last {v['window_days']} days)", "",
        f"Total: {v['total']} (AegisSOC rules: {v['aegissoc_rule_alerts']})", "",
        "| Day | Alerts |", "|---|---|", *[f"| {d} | {n} |" for d, n in v["per_day"].items()], "",
        "| Agent | Alerts |", "|---|---|", *[f"| {md(a)} | {n} |" for a, n in v["per_agent"].items()], "",
        "| Level band | Alerts |", "|---|---|", *[f"| {k} | {n} |" for k, n in v["by_level"].items()], "",
        "| Top rule | Count | Description |", "|---|---|---|",
        *[f"| {md(r['rule_id'])} | {r['count']} | {md(r['description'])} |" for r in v["top_rules"]], "",
        "## Availability and cases", "",
        "| Metric | Value | Sample |", "|---|---|---|",
        f"| Agents all active | {fmt(av['agents_all_active_ratio'])} | {av['health_samples']} health snapshots ({fmt(av['first_sample'])} .. {fmt(av['last_sample'])}) |",
        f"| Health snapshots with FAIL | {av['overall_fail_samples']} | |",
        f"| Cases open / closed | {c['open']} / {c['closed']} | {c['cases']} cases |",
        f"| Resolution time median / max (min) | {fmt(c['resolution_minutes']['median'])} / {fmt(c['resolution_minutes']['max'])} | closed cases |",
        f"| Analyst-labelled false positives | {c['analyst_labelled_false_positives']} | count, not a rate |", "",
        "## Resources and storage", "",
        "| Container | CPU % | Memory | Limit |", "|---|---|---|---|",
        *[f"| {r['name']} | {r['cpu_percent']} | {r['mem_usage']} | {r['mem_limit']} |" for r in m["resources"]], "",
        f"Indexer data: {fmt(st['indices_bytes'])} bytes; disk used {fmt(st['disk_percent'])}%; "
        f"upper-bound bytes/alert {fmt(st['bytes_per_alert_upper_bound'])} (includes non-alert indices).",
    ]
    return "\n".join(lines) + "\n"
