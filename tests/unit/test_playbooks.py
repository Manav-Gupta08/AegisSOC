"""Response playbook and response-action tests. Cases and alerts are SYNTHETIC fixtures; nothing touches an endpoint."""
from pathlib import Path

import pytest
import yaml

from aegissoc import cases, playbooks, reporting
from aegissoc.cases import CaseError, record, verify
from aegissoc.playbooks import PlaybookError, load_playbooks, proposal, simulation_plan

ROOT = Path(__file__).resolve().parents[2]
ALERT = {"alert_id": "a1", "index": "wazuh-alerts-4.x-2026.10.13", "timestamp": "2026-10-13T11:00:37.012+0000",
         "rule_id": "100200", "rule_level": 10, "rule_description": "sudoers changed", "agent": "lab-linux"}


def investigating_case():
    c = cases.new_case("CASE-20261013-001", "Sudoers change", "high", "alice", at="2026-10-13T11:05:00+00:00")
    record(c, "alice", "transition", {"to": "triage"})
    record(c, "alice", "add_alert", {"alert": ALERT})
    record(c, "alice", "transition", {"to": "investigating"})
    return c


@pytest.fixture(scope="module")
def pb001():
    return load_playbooks(ROOT)["PB-001"]


def propose(c, pb, step=3, target="/etc/sudoers.d/x", actor="alice", endpoint="lab-linux"):
    detail = proposal(pb, step, c, endpoint, target, "remove unauthorized grant")
    return record(c, actor, "propose_action", {"action": {"action_id": cases.next_action_id(c), **detail}})


def test_repository_playbooks_are_valid():
    assert {"PB-001", "PB-002", "PB-003"} <= set(load_playbooks(ROOT))


def write(tmp_path, data):
    (tmp_path / "playbooks").mkdir(exist_ok=True)
    path = tmp_path / "playbooks" / f"{data.get('id', 'x')}-t.yml"
    path.write_text(yaml.safe_dump(data))
    return path


BASE = {"id": "PB-900", "title": "t", "description": "d", "applies_to_rules": ["100200"],
        "steps": [{"kind": "action", "action": "isolate_host", "text": "x"}]}


@pytest.mark.parametrize("overrides,match", [
    ({"id": "PB-9"}, "PB-NNN"),
    ({"applies_to_rules": ["123456"]}, "unknown rules"),
    ({"steps": [{"kind": "script", "text": "x"}]}, "kind"),
    ({"steps": [{"kind": "action", "action": "rm_rf", "text": "x"}]}, "action must be one of"),
    ({"steps": []}, "missing steps"),
])
def test_invalid_playbooks_rejected(tmp_path, overrides, match):
    data = {**BASE, **overrides}
    with pytest.raises(PlaybookError, match=match):
        playbooks.validate_playbook(data, write(tmp_path, data), {100200})


@pytest.mark.parametrize("step,target,match", [
    (1, "/etc/sudoers.d/x", "not an action step"),
    (3, None, "needs --target"),
    (3, "etc/sudoers.d/x", "absolute"),
    (3, "/etc/sudoers.d/../shadow", "normalized"),
    (3, "/etc", "system directory"),
    (4, "root", "non-root"),
    (4, "bad name;rm", "invalid account"),
])
def test_proposal_validates_targets(pb001, step, target, match):
    with pytest.raises(PlaybookError, match=match):
        proposal(pb001, step, investigating_case(), "lab-linux", target, "p")


@pytest.mark.parametrize("value,ok", [("203.0.113.7", True), ("127.0.0.1", False), ("0.0.0.0", False), ("nope", False)])
def test_block_ip_targets(value, ok):
    if ok:
        assert playbooks._ip(value) == value
    else:
        with pytest.raises(PlaybookError):
            playbooks._ip(value)


def test_playbook_must_apply_to_case_alerts():
    pb002 = load_playbooks(ROOT)["PB-002"]
    with pytest.raises(PlaybookError, match="applies to rules"):
        proposal(pb002, 3, investigating_case(), "lab-linux", "alice", "p")


def test_full_response_lifecycle_is_audited_and_simulated(pb001):
    c = investigating_case()
    propose(c, pb001)
    record(c, "bob", "approve_action", {"action_id": "ACT-001"})
    plan = simulation_plan(c["response_actions"][0])
    record(c, "bob", "execute_action", {"action_id": "ACT-001", "mode": "simulation", "plan": plan})
    act = c["response_actions"][0]
    assert act["state"] == "simulated" and act["proposed_by"] == "alice" and act["approved_by"] == "bob"
    assert act["plan"].startswith("on lab-linux: move /etc/sudoers.d/x") and "no change" in act["result"]
    cases.validate(c)
    assert verify(c) == []
    md = reporting.render_markdown(c, {"audit": [], "evidence": []}, [])
    assert "ACT-001" in md and "SIMULATED" in md


def test_proposer_cannot_approve_own_action(pb001):
    c = investigating_case()
    propose(c, pb001)
    with pytest.raises(CaseError, match="different analyst"):
        record(c, "alice", "approve_action", {"action_id": "ACT-001"})


@pytest.mark.parametrize("before,match", [
    ([], "is proposed; expected approved"),
    ([("bob", "approve_action"), ("bob", "execute_action")], "is simulated; expected approved"),
])
def test_execute_requires_approval_and_runs_once(pb001, before, match):
    c = investigating_case()
    propose(c, pb001)
    for actor, action in before:
        detail = {"action_id": "ACT-001", "mode": "simulation", "plan": "p"}
        record(c, actor, action, detail if action == "execute_action" else {"action_id": "ACT-001"})
    with pytest.raises(CaseError, match=match):
        record(c, "bob", "execute_action", {"action_id": "ACT-001", "mode": "simulation", "plan": "p"})


def test_real_execution_is_refused(pb001):
    c = investigating_case()
    propose(c, pb001)
    record(c, "bob", "approve_action", {"action_id": "ACT-001"})
    with pytest.raises(CaseError, match="only simulated"):
        record(c, "bob", "execute_action", {"action_id": "ACT-001", "mode": "live", "plan": "p"})


def test_duplicate_proposal_refused_until_rejected(pb001):
    c = investigating_case()
    propose(c, pb001)
    with pytest.raises(CaseError, match="duplicate of ACT-001"):
        propose(c, pb001)
    with pytest.raises(CaseError, match="reason"):
        record(c, "bob", "reject_action", {"action_id": "ACT-001"})
    record(c, "bob", "reject_action", {"action_id": "ACT-001", "reason": "authorized change"})
    propose(c, pb001)
    assert [a["action_id"] for a in c["response_actions"]] == ["ACT-001", "ACT-002"]


def test_target_endpoint_must_be_affected(pb001):
    with pytest.raises(CaseError, match="not an affected endpoint"):
        propose(investigating_case(), pb001, endpoint="other-host")


def test_proposals_need_an_active_investigation(pb001):
    c = cases.new_case("CASE-20261013-002", "Triage only", "low", "alice")
    record(c, "alice", "transition", {"to": "triage"})
    record(c, "alice", "add_alert", {"alert": ALERT})
    with pytest.raises(CaseError, match="only while"):
        propose(c, pb001)


def test_pending_actions_block_resolution(pb001):
    c = investigating_case()
    propose(c, pb001)
    record(c, "alice", "set", {"field": "classification", "value": "test_activity"})
    record(c, "alice", "set", {"field": "findings", "value": "scenario"})
    with pytest.raises(CaseError, match="pending response actions"):
        record(c, "alice", "transition", {"to": "resolved"})
    record(c, "bob", "reject_action", {"action_id": "ACT-001", "reason": "authorized scenario"})
    record(c, "alice", "transition", {"to": "resolved"})


def test_tampered_action_state_is_detected(pb001):
    c = investigating_case()
    propose(c, pb001)
    c["response_actions"][0]["state"] = "approved"
    assert any("response_actions" in p for p in verify(c))
