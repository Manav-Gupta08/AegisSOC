from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .detections import load_metadata
from .scenarios import load_scenarios


def build_matrix(root: Path, scenario_report: dict[str, Any] | None) -> dict[str, Any]:
    meta = load_metadata(root)
    scenarios = load_scenarios(root)
    results = {r["scenario_id"]: r for r in (scenario_report or {}).get("results", [])}

    rows = []
    for rule_id, m in sorted(meta.items()):
        if m.get("kind", "detection") != "detection":
            continue
        rid = str(rule_id)
        positive = [s for s in scenarios.values() if rid in map(str, s["expected"].get("detection_rules") or [])]
        negative = [s for s in scenarios.values() if rid in map(str, s["expected"].get("forbidden_rules") or [])]
        logtests = (m["tests"].get("logtest") or [])
        observed = [results[s["id"]] for s in positive if s["id"] in results]
        rows.append({
            "rule_id": rule_id,
            "title": m["title"],
            "techniques": m["mitre"],
            "rule_status": m["status"],
            "telemetry": m["telemetry"],
            "logtest_cases": len(logtests),
            "positive_scenarios": [s["id"] for s in positive],
            "negative_scenarios": [s["id"] for s in negative],
            "scenario_results": {sid: results[sid]["status"] for sid in [s["id"] for s in positive + negative] if sid in results},
            "observed_in_lab": any(r["status"] == "PASSED" for r in observed),
            "min_latency_s": min((r["first_detection_latency_s"] for r in observed if r.get("first_detection_latency_s") is not None), default=None),
            "limitations": m["limitations"],
        })
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scenario_report_generated_at": (scenario_report or {}).get("generated_at"),
        "rows": rows,
    }


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;").replace("\n", " ")


def render_markdown(matrix: dict[str, Any]) -> str:
    lines = [
        "# Detection Coverage Matrix",
        "",
        f"Generated {matrix['generated_at']} from rule metadata, scenario manifests, and the scenario report "
        f"of {matrix['scenario_report_generated_at'] or 'N/A (no report)'}.",
        "",
        "Columns are deliberately separate: a documented technique, an existing rule, a passing test, and an",
        "observation in this lab are different claims. None of them measures real-world detection rate.",
        "",
        "| Rule | Technique(s) | Rule exists | Logtest cases | Scenarios (+/-) | Last scenario result | Observed in lab | Min latency (s) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in matrix["rows"]:
        results = ", ".join(f"{k}: {v}" for k, v in r["scenario_results"].items()) or "not run"
        lines.append(
            f"| {r['rule_id']} {_md_escape(r['title'])} | {', '.join(r['techniques'])} | yes ({r['rule_status']}) "
            f"| {r['logtest_cases']} | +{len(r['positive_scenarios'])} / -{len(r['negative_scenarios'])} "
            f"| {_md_escape(results)} | {'yes' if r['observed_in_lab'] else 'no'} "
            f"| {r['min_latency_s'] if r['min_latency_s'] is not None else '-'} |")
    lines += ["", "## Known gaps per rule", ""]
    for r in matrix["rows"]:
        lines.append(f"- **{r['rule_id']}**: " + "; ".join(_md_escape(x) for x in r["limitations"]))
    return "\n".join(lines) + "\n"


def latest_report(reports_dir: Path) -> dict[str, Any] | None:
    files = sorted(reports_dir.glob("scenarios-*.json"))
    return json.loads(files[-1].read_text(encoding="utf-8")) if files else None
