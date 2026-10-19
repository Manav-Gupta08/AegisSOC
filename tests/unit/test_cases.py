"""Case workflow tests. Alerts here are SYNTHETIC fixtures, not lab telemetry."""
import copy
import json
from datetime import datetime, timezone

import pytest

from aegissoc import cases, reporting
from aegissoc.cases import CaseError, CaseStore, new_case, record, verify

ALERT = {"alert_id": "a1", "index": "wazuh-alerts-4.x-2026.10.13", "timestamp": "2026-10-13T11:00:37.012+0000",
         "rule_id": "100200", "rule_level": 10, "rule_description": "sudoers changed", "mitre": ["T1548.003"], "agent": "lab-linux"}


def fresh():
    return new_case("CASE-20261013-001", "Test case", "high", "tester", at="2026-10-13T11:05:00+00:00")


def investigated():
    c = fresh()
    record(c, "t", "transition", {"from": "new", "to": "triage"})
    record(c, "t", "add_alert", {"alert": ALERT})
    record(c, "t", "transition", {"from": "triage", "to": "investigating"})
    return c


def test_full_lifecycle_to_closed():
    c = investigated()
    record(c, "t", "recommend", {"text": "Review sudoers drop-ins"})
    record(c, "t", "transition", {"from": "investigating", "to": "containment_recommended"})
    record(c, "t", "set", {"field": "classification", "value": "test_activity"})
    record(c, "t", "set", {"field": "findings", "value": "Scenario LNX-003"})
    record(c, "t", "transition", {"from": "containment_recommended", "to": "resolved"})
    record(c, "t", "set", {"field": "closure_reason", "value": "Authorized test"})
    record(c, "t", "transition", {"from": "resolved", "to": "closed"})
    cases.validate(c)
    assert c["status"] == "closed" and c["affected_endpoints"] == ["lab-linux"] and verify(c) == []


@pytest.mark.parametrize("steps,match", [
    ([("transition", {"to": "resolved"})], "invalid transition"),
    ([("transition", {"to": "triage"}), ("transition", {"to": "investigating"})], "source alert"),
])
def test_invalid_transitions(steps, match):
    c = fresh()
    with pytest.raises(CaseError, match=match):
        for action, detail in steps:
            record(c, "t", action, detail)


def test_preconditions_enforced():
    c = investigated()
    with pytest.raises(CaseError, match="recommendation"):
        record(c, "t", "transition", {"to": "containment_recommended"})
    with pytest.raises(CaseError, match="classification and findings"):
        record(c, "t", "transition", {"to": "resolved"})


def test_true_positive_requires_lessons_learned():
    c = investigated()
    for f, v in (("classification", "true_positive"), ("findings", "x"), ("closure_reason", "done")):
        record(c, "t", "set", {"field": f, "value": v})
    record(c, "t", "transition", {"to": "resolved"})
    with pytest.raises(CaseError, match="lessons_learned"):
        record(c, "t", "transition", {"to": "closed"})


def test_rejected_mutation_leaves_case_unchanged():
    c = fresh()
    before = copy.deepcopy(c)
    with pytest.raises(CaseError):
        record(c, "t", "transition", {"to": "closed"})
    assert c == before


def test_closed_case_is_immutable_except_corrections():
    c = investigated()
    record(c, "t", "set", {"field": "classification", "value": "false_positive"})
    record(c, "t", "set", {"field": "closure_reason", "value": "benign admin change"})
    record(c, "t", "transition", {"to": "false_positive"})
    for action, detail in (("add_alert", {"alert": {**ALERT, "alert_id": "a2"}}), ("set", {"field": "severity", "value": "low"})):
        with pytest.raises(CaseError, match="only corrections"):
            record(c, "t", action, detail)
    with pytest.raises(CaseError, match="reason"):
        record(c, "t", "correction", {"field": "severity", "value": "low"})
    record(c, "t", "correction", {"field": "severity", "value": "low", "reason": "mis-triaged"})
    assert c["severity"] == "low" and c["audit"][-1]["action"] == "correction" and verify(c) == []


def test_tamper_body_edit_detected():
    c = investigated()
    c["severity"] = "low"
    assert any("severity" in p for p in verify(c))


def test_tamper_audit_edit_and_deletion_detected():
    c = investigated()
    edited = copy.deepcopy(c)
    edited["audit"][1]["actor"] = "someone-else"
    assert any("hash mismatch" in p for p in verify(edited))
    deleted = copy.deepcopy(c)
    del deleted["audit"][1]
    assert any("prev_hash" in p or "seq" in p for p in verify(deleted))


def test_schema_rejects_unknown_fields():
    c = fresh()
    c["contained"] = True
    with pytest.raises(CaseError, match="schema"):
        cases.validate(c)


def test_store_roundtrip_ids_and_tamper_on_load(tmp_path):
    store = CaseStore(tmp_path)
    day = datetime(2026, 10, 13, tzinfo=timezone.utc)
    assert store.next_id(day) == "CASE-20261013-001"
    c = investigated()
    store.save(c, None)
    assert store.next_id(day) == "CASE-20261013-002"
    assert store.load(c["case_id"]) == c
    path = store.path(c["case_id"])
    data = json.loads(path.read_text())
    data["status"] = "closed"
    path.write_text(json.dumps(data))
    with pytest.raises(CaseError, match="integrity"):
        store.load(c["case_id"])


def test_concurrent_update_is_rejected(tmp_path):
    # Regression: interleaved CLI invocations could overwrite each other's audit entries.
    store = CaseStore(tmp_path)
    store.save(investigated(), None)
    first, second = store.load("CASE-20261013-001"), store.load("CASE-20261013-001")
    base = first["audit"][-1]["hash"]
    record(first, "a", "note", {"text": "one"})
    store.save(first, base)
    record(second, "b", "note", {"text": "two"})
    with pytest.raises(CaseError, match="modified by another process"):
        store.save(second, base)
    assert [n["text"] for n in store.load("CASE-20261013-001")["notes"]] == ["one"]
    with pytest.raises(CaseError, match="modified by another process"):
        store.save(investigated(), None)


def test_store_rejects_path_traversal_ids(tmp_path):
    with pytest.raises(CaseError):
        CaseStore(tmp_path).path("../../etc/passwd")


def test_evidence_files_hashed_and_verified(tmp_path):
    store = CaseStore(tmp_path)
    c = investigated()
    ev = store.add_file_evidence(c, "t", "alert", b'{"x":1}', "raw alert")
    assert ev["evidence_id"] == "EV-001" and store.verify_evidence_files(c) == []
    (store.dir / ev["reference"]).write_bytes(b'{"x":2}')
    assert any("mismatch" in p for p in store.verify_evidence_files(c))


def test_evidence_blocked_after_closure(tmp_path):
    store = CaseStore(tmp_path)
    c = investigated()
    c["status"] = "closed"
    with pytest.raises(CaseError, match="immutable"):
        store.add_file_evidence(c, "t", "alert", b"x", "late")


def test_alert_from_hit():
    hit = {"_id": "abc", "_index": "wazuh-alerts-x", "_source": {"timestamp": "t", "agent": {"name": "n"},
           "rule": {"id": "5557", "level": 5, "description": "d", "mitre": {"id": ["T1110.001"]}}}}
    assert cases.alert_from_hit(hit)["mitre"] == ["T1110.001"]


def test_report_escapes_untrusted_text_and_redacts():
    c = investigated()
    record(c, "t", "note", {"text": "<img src=x onerror=alert(1)> | `rm -rf` lab-linux"})
    md = reporting.render_markdown(c, {"audit": [], "evidence": []}, ["lab-linux"])
    assert "<img" not in md and "&lt;img" in md and "\\|" in md and "lab-linux" not in md
    assert "Recommendations (not executed)" in md and "VERIFIED" in md


def test_terminal_neutralizes_escape_sequences():
    out = reporting.terminal("user \x1b]0;pwned\x07\x1b[2J\r\nnext\x9b")
    assert not any(ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f for ch in out)
    assert out == "user \\x1b]0;pwned\\x07\\x1b[2J\\x0d\\x0anext\\x9b"
