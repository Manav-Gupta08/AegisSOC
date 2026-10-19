"""Case report rendering (Markdown/JSON). All case text is treated as untrusted and escaped."""
from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from typing import Any

from .redact import redact

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

LIMITATIONS = [
    "Alerts reflect only telemetry the agents collected; absence of an alert is not evidence of absence.",
    "Linux FIM on the WSL2 endpoint has no actor attribution (kernel audit unavailable).",
    "Recommendations are not actions: AegisSOC performs no automated containment.",
]


def md(text: Any) -> str:
    """Escape untrusted text for a Markdown table cell or paragraph (no HTML, no table breaks)."""
    escaped = html.escape(str(text), quote=False)
    for ch in ("\\", "|", "`", "*", "_", "[", "]"):
        escaped = escaped.replace(ch, "\\" + ch)
    return " ".join(escaped.splitlines())


def terminal(text: Any) -> str:
    """Make untrusted text safe to print: control characters (ANSI escapes, CR, newlines) become visible \\xNN."""
    return _CONTROL_CHARS.sub(lambda m: f"\\x{ord(m.group()):02x}", str(text))


def _ts(value: str) -> datetime:
    v = value.replace("Z", "+00:00")
    if len(v) > 5 and v[-5] in "+-" and v[-3] != ":":
        v = v[:-2] + ":" + v[-2:]
    parsed = datetime.fromisoformat(v)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def timeline(case: dict[str, Any]) -> list[tuple[datetime, str, str]]:
    rows = [(_ts(a["timestamp"]), "alert", f"rule {a['rule_id']} (level {a['rule_level']}) on {a['agent']}: {a['rule_description']}")
            for a in case["source_alerts"]]
    for e in case["audit"]:
        d = e["detail"]
        summary = {
            "created": lambda: f"case created: {d['title']}",
            "transition": lambda: f"status -> {d['to']}" + (f" ({d['reason']})" if d.get("reason") else ""),
            "set": lambda: f"{d['field']} set",
            "correction": lambda: f"CORRECTION of {d['field']}: {d.get('reason', '')}",
            "note": lambda: "analyst note",
            "add_alert": lambda: f"alert {d['alert']['alert_id']} attached",
            "add_evidence": lambda: f"evidence {d['evidence']['evidence_id']} collected",
            "recommend": lambda: "recommendation added",
        }.get(e["action"], lambda: e["action"])()
        rows.append((_ts(e["at"]), f"audit #{e['seq']} ({e['actor']})", summary))
    return sorted(rows, key=lambda r: r[0])


def render_markdown(case: dict[str, Any], integrity: dict[str, Any], redact_terms: list[str]) -> str:
    c = redact(case, redact_terms)
    lines = [
        f"# {md(c['case_id'])}: {md(c['title'])}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Status | {md(c['status'])} |",
        f"| Severity | {md(c['severity'])} |",
        f"| Classification | {md(c['classification'])} |",
        f"| Confidence | {md(c['confidence'])} |",
        f"| Created | {md(c['created_at'])} |",
        f"| Affected endpoints | {md(', '.join(c['affected_endpoints']) or 'none recorded')} |",
        f"| Audit trail | {'VERIFIED' if not integrity['audit'] else 'FAILED: ' + md('; '.join(integrity['audit']))} |",
        f"| Evidence files | {'VERIFIED' if not integrity['evidence'] else 'FAILED: ' + md('; '.join(integrity['evidence']))} |",
        "",
        "## Source alerts",
        "",
        "| Time | Rule | Level | ATT&CK | Agent | Description |",
        "|---|---|---|---|---|---|",
    ]
    lines += [f"| {md(a['timestamp'])} | {md(a['rule_id'])} | {a['rule_level']} | {md(', '.join(a.get('mitre', [])))} "
              f"| {md(a['agent'])} | {md(a['rule_description'])} |" for a in c["source_alerts"]] or ["| - | - | - | - | - | none |"]
    lines += ["", "## Evidence", "", "| ID | Kind | Reference | SHA-256 | Description |", "|---|---|---|---|---|"]
    lines += [f"| {md(e['evidence_id'])} | {md(e['kind'])} | {md(e['reference'])} | `{e['sha256'][:16]}…` | {md(e.get('description', ''))} |"
              for e in c["evidence"]] or ["| - | - | - | - | none |"]
    lines += ["", "## Timeline", "", "| Time (UTC) | Source | Event |", "|---|---|---|"]
    lines += [f"| {t.astimezone(timezone.utc).isoformat(timespec='seconds')} | {md(src)} | {md(text)} |" for t, src, text in timeline(c)]
    lines += ["", "## Findings", "", md(c.get("findings") or "None recorded."), ""]
    if c.get("escalation_rationale"):
        lines += ["## Escalation rationale", "", md(c["escalation_rationale"]), ""]
    lines += ["## Recommendations (not executed)", ""]
    lines += [f"- {md(r)}" for r in c["recommendations"]] or ["- None."]
    lines += ["", "## Analyst notes", ""]
    lines += [f"- {md(n['at'])} {md(n['author'])}: {md(n['text'])}" for n in c["notes"]] or ["- None."]
    if c.get("closure_reason"):
        lines += ["", "## Closure", "", md(c["closure_reason"])]
    if c.get("lessons_learned"):
        lines += ["", "## Lessons learned", "", md(c["lessons_learned"])]
    lines += ["", "## Limitations", ""] + [f"- {md(x)}" for x in LIMITATIONS]
    return "\n".join(lines) + "\n"
