"""Incident cases: schema-validated JSON with a hash-chained, replayable audit trail.

Every mutation is an audit entry; the case body is derived by replaying the audit log. Verification
replays the log and compares it with the stored body, so edits outside the tool are detected.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "case-1.0.json"
CASE_ID = re.compile(r"^CASE-\d{8}-\d{3}$")
GENESIS = "0" * 64

TRANSITIONS: dict[str, set[str]] = {
    "new": {"triage"},
    "triage": {"investigating", "false_positive"},
    "investigating": {"containment_recommended", "resolved", "false_positive"},
    "containment_recommended": {"resolved", "investigating"},
    "resolved": {"closed", "investigating"},
    "closed": set(),
    "false_positive": set(),
}
TERMINAL = {"closed", "false_positive"}
SETTABLE = {"severity", "classification", "confidence", "findings", "escalation_rationale", "closure_reason", "lessons_learned"}
RESPONSE_STATUSES = {"investigating", "containment_recommended"}
PENDING_ACTION_STATES = {"proposed", "approved"}


class CaseError(ValueError):
    pass


def next_action_id(case: dict[str, Any]) -> str:
    return f"ACT-{len(case.get('response_actions', [])) + 1:03d}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _entry_hash(entry: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical({k: entry[k] for k in ("seq", "at", "actor", "action", "detail", "prev_hash")})).hexdigest()


def _blank() -> dict[str, Any]:
    return {"schema_version": "1.0", "status": "new", "classification": "unclassified", "confidence": "low",
            "affected_endpoints": [], "source_alerts": [], "evidence": [], "notes": [], "recommendations": []}


def _check_transition(case: dict[str, Any], to: str) -> None:
    current = case["status"]
    if to not in TRANSITIONS[current]:
        raise CaseError(f"invalid transition {current} -> {to}; allowed: {sorted(TRANSITIONS[current]) or 'none (terminal)'}")
    if to == "investigating" and current == "triage" and not (case["source_alerts"] or case["evidence"]):
        raise CaseError("cannot investigate without at least one source alert or evidence item")
    if to == "containment_recommended" and not case["recommendations"]:
        raise CaseError("add at least one recommendation before containment_recommended")
    if to == "resolved" and (case["classification"] == "unclassified" or not case.get("findings")):
        raise CaseError("set classification and findings before resolving")
    if to == "closed":
        if not case.get("closure_reason"):
            raise CaseError("set closure_reason before closing")
        if case["classification"] == "true_positive" and not case.get("lessons_learned"):
            raise CaseError("true positives require lessons_learned before closing")
    if to == "false_positive" and (case["classification"] != "false_positive" or not case.get("closure_reason")):
        raise CaseError("set classification=false_positive and closure_reason first")
    pending = [a["action_id"] for a in case.get("response_actions", []) if a["state"] in PENDING_ACTION_STATES]
    if to in ("resolved", "false_positive") and pending:
        raise CaseError(f"decide pending response actions first (execute or reject): {pending}")


def _response_action(case: dict[str, Any], action_id: str, states: set[str]) -> dict[str, Any]:
    found = next((a for a in case.get("response_actions", []) if a["action_id"] == action_id), None)
    if found is None:
        raise CaseError(f"unknown response action {action_id!r}")
    if found["state"] not in states:
        raise CaseError(f"{action_id} is {found['state']}; expected {' or '.join(sorted(states))}")
    return found


def _apply_response(case: dict[str, Any], entry: dict[str, Any]) -> None:
    """Response actions: proposed -> approved (by someone else) -> simulated, or -> rejected. Nothing is executed."""
    action, d, actor, at = entry["action"], entry["detail"], entry["actor"], entry["at"]
    if action == "propose_action":
        if case["status"] not in RESPONSE_STATUSES:
            raise CaseError(f"response actions can be proposed only while {' or '.join(sorted(RESPONSE_STATUSES))}")
        proposed = d["action"]
        if proposed["endpoint"] not in case["affected_endpoints"]:
            raise CaseError(f"endpoint {proposed['endpoint']!r} is not an affected endpoint of this case")
        if proposed["action_id"] != next_action_id(case):
            raise CaseError(f"action id must be {next_action_id(case)}")
        actions = case.setdefault("response_actions", [])
        key = (proposed["action_type"], proposed["endpoint"], proposed["target"])
        duplicate = next((a for a in actions if (a["action_type"], a["endpoint"], a["target"]) == key
                          and a["state"] != "rejected"), None)
        if duplicate:
            raise CaseError(f"duplicate of {duplicate['action_id']} ({duplicate['state']})")
        actions.append({**proposed, "state": "proposed", "proposed_by": actor, "proposed_at": at})
    elif action == "approve_action":
        target = _response_action(case, d["action_id"], {"proposed"})
        if actor == target["proposed_by"]:
            raise CaseError("approval requires a different analyst than the proposer")
        target.update(state="approved", approved_by=actor, approved_at=at)
    elif action == "reject_action":
        target = _response_action(case, d["action_id"], PENDING_ACTION_STATES)
        if not d.get("reason"):
            raise CaseError("rejecting a response action requires a reason")
        target.update(state="rejected", rejected_by=actor, rejected_at=at, rejection_reason=d["reason"])
    elif action == "execute_action":
        target = _response_action(case, d["action_id"], {"approved"})
        if d.get("mode") != "simulation":
            raise CaseError("only simulated execution is supported; AegisSOC never changes endpoints")
        target.update(state="simulated", executed_by=actor, executed_at=at, plan=d["plan"],
                      result="simulated: no change was made to the endpoint")


def _apply(case: dict[str, Any], entry: dict[str, Any]) -> None:
    """Apply one audit entry to the case body. Used for both mutation and replay verification."""
    action, d = entry["action"], entry["detail"]
    if action == "created":
        case.update(case_id=d["case_id"], title=d["title"], severity=d["severity"], created_at=entry["at"])
        return
    if case["status"] in TERMINAL and action not in ("correction", "note"):
        raise CaseError(f"case is {case['status']}; only corrections and notes are allowed")
    if action == "transition":
        _check_transition(case, d["to"])
        case["status"] = d["to"]
    elif action in ("set", "correction"):
        if d["field"] not in SETTABLE:
            raise CaseError(f"field {d['field']!r} cannot be set; settable: {sorted(SETTABLE)}")
        if action == "correction" and not d.get("reason"):
            raise CaseError("corrections require a reason")
        case[d["field"]] = d["value"]
    elif action == "note":
        case["notes"].append({"at": entry["at"], "author": entry["actor"], "text": d["text"]})
    elif action == "add_alert":
        if any(a["alert_id"] == d["alert"]["alert_id"] for a in case["source_alerts"]):
            raise CaseError(f"alert {d['alert']['alert_id']} already attached")
        case["source_alerts"].append(d["alert"])
        if d["alert"]["agent"] not in case["affected_endpoints"]:
            case["affected_endpoints"].append(d["alert"]["agent"])
    elif action == "add_evidence":
        case["evidence"].append(d["evidence"])
    elif action == "recommend":
        case["recommendations"].append(d["text"])
    elif action in ("propose_action", "approve_action", "reject_action", "execute_action"):
        _apply_response(case, entry)
    else:
        raise CaseError(f"unknown audit action {action!r}")


def record(case: dict[str, Any], actor: str, action: str, detail: dict[str, Any], at: str | None = None) -> dict[str, Any]:
    """Apply a mutation and append its audit entry. The case is unchanged if the mutation is rejected."""
    audit = case.setdefault("audit", [])
    entry = {"seq": len(audit) + 1, "at": at or _now(), "actor": actor, "action": action, "detail": detail,
             "prev_hash": audit[-1]["hash"] if audit else GENESIS}
    trial = copy.deepcopy(case)
    _apply(trial, entry)
    entry["hash"] = _entry_hash(entry)
    trial["audit"].append(entry)
    case.clear()
    case.update(trial)
    return entry


def new_case(case_id: str, title: str, severity: str, actor: str, at: str | None = None) -> dict[str, Any]:
    if not CASE_ID.match(case_id):
        raise CaseError(f"invalid case id {case_id!r}")
    case = _blank()
    case["audit"] = []
    record(case, actor, "created", {"case_id": case_id, "title": title, "severity": severity}, at=at)
    validate(case)
    return case


def verify(case: dict[str, Any]) -> list[str]:
    """Return integrity problems: broken hash chain, or a body that differs from the replayed audit log."""
    problems = []
    prev = GENESIS
    replay = _blank()
    for i, entry in enumerate(case.get("audit", []), start=1):
        if entry.get("seq") != i:
            problems.append(f"audit seq {entry.get('seq')} at position {i}")
        if entry.get("prev_hash") != prev:
            problems.append(f"audit entry {i}: prev_hash does not link to entry {i - 1}")
        if entry.get("hash") != _entry_hash(entry):
            problems.append(f"audit entry {i}: hash mismatch (entry modified)")
        prev = entry.get("hash", "")
        try:
            _apply(replay, entry)
        except (CaseError, KeyError) as exc:
            problems.append(f"audit entry {i}: replay failed: {exc}")
    body = {k: v for k, v in case.items() if k != "audit"}
    for key in sorted(set(body) | set(replay)):
        if body.get(key) != replay.get(key):
            problems.append(f"field {key!r} differs from the audit trail (edited outside the tool?)")
    return problems


def validate(case: dict[str, Any]) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        jsonschema.validate(case, schema)
    except jsonschema.ValidationError as exc:
        raise CaseError(f"schema violation at {'/'.join(map(str, exc.absolute_path)) or '<root>'}: {exc.message}") from exc


class CaseStore:
    def __init__(self, root: Path) -> None:
        self.dir = root / "cases"

    def path(self, case_id: str) -> Path:
        if not CASE_ID.match(case_id):
            raise CaseError(f"invalid case id {case_id!r}")
        return self.dir / f"{case_id}.json"

    def evidence_dir(self, case_id: str) -> Path:
        return self.dir / case_id / "evidence"

    def next_id(self, day: datetime | None = None) -> str:
        stamp = (day or datetime.now(timezone.utc)).strftime("%Y%m%d")
        existing = [int(p.stem[-3:]) for p in self.dir.glob(f"CASE-{stamp}-*.json")] if self.dir.is_dir() else []
        return f"CASE-{stamp}-{max(existing, default=0) + 1:03d}"

    def load(self, case_id: str) -> dict[str, Any]:
        path = self.path(case_id)
        if not path.is_file():
            raise CaseError(f"{case_id} not found")
        case = json.loads(path.read_text(encoding="utf-8"))
        validate(case)
        problems = verify(case)
        if problems:
            raise CaseError(f"{case_id} failed integrity verification: {problems}")
        return case

    def head(self, case_id: str) -> str | None:
        """Hash of the last audit entry on disk, or None if the case does not exist yet."""
        path = self.path(case_id)
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))["audit"][-1]["hash"]

    def save(self, case: dict[str, Any], base_head: str | None) -> Path:
        """Save only if the on-disk case is still at base_head (None for a new case); prevents lost updates."""
        validate(case)
        problems = verify(case)
        if problems:
            raise CaseError(f"refusing to save inconsistent case: {problems}")
        current = self.head(case["case_id"])
        if current != base_head:
            raise CaseError(f"{case['case_id']} was modified by another process since it was loaded; reload and retry")
        path = self.path(case["case_id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(case, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)
        return path

    def list(self) -> list[dict[str, Any]]:
        if not self.dir.is_dir():
            return []
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.dir.glob("CASE-*.json"))]

    def add_file_evidence(self, case: dict[str, Any], actor: str, kind: str, content: bytes, description: str) -> dict[str, Any]:
        if case["status"] in TERMINAL:
            raise CaseError(f"case is {case['status']}; evidence is immutable after closure")
        ev_id = f"EV-{len(case['evidence']) + 1:03d}"
        folder = self.evidence_dir(case["case_id"])
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"{ev_id}.json"
        if target.exists():
            raise CaseError(f"{target} already exists; evidence files are never overwritten")
        target.write_bytes(content)
        evidence = {"evidence_id": ev_id, "kind": kind, "reference": target.relative_to(self.dir).as_posix(),
                    "sha256": hashlib.sha256(content).hexdigest(), "collected_at": _now(), "description": description}
        record(case, actor, "add_evidence", {"evidence": evidence})
        return evidence

    def verify_evidence_files(self, case: dict[str, Any]) -> list[str]:
        problems = []
        for ev in case["evidence"]:
            path = self.dir / ev["reference"]
            if not path.is_file():
                problems.append(f"{ev['evidence_id']}: file missing ({ev['reference']})")
            elif hashlib.sha256(path.read_bytes()).hexdigest() != ev["sha256"]:
                problems.append(f"{ev['evidence_id']}: SHA-256 mismatch (file modified)")
        return problems


def alert_from_hit(hit: dict[str, Any]) -> dict[str, Any]:
    src = hit["_source"]
    rule = src.get("rule", {})
    return {
        "alert_id": hit["_id"],
        "index": hit["_index"],
        "timestamp": src.get("timestamp", ""),
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0)),
        "rule_description": rule.get("description", ""),
        "mitre": list((rule.get("mitre") or {}).get("id", [])),
        "agent": (src.get("agent") or {}).get("name", ""),
    }
