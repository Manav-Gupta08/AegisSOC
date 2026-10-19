"""Telemetry source checks against SYNTHETIC agents and alerts; no stack is contacted."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegissoc import telemetry
from aegissoc.agentconfig import AgentConfigError, assign_group
from aegissoc.clients import ServiceError
from aegissoc.health import FAIL, NOT_VERIFIED, PASS, WARNING

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 19, 12, 0, tzinfo=timezone.utc)
SOURCES = [{"id": "linux-fim", "agent_group": "linux", "description": "FIM", "rule_groups": ["syscheck"],
            "max_silence_hours": 24},
           {"id": "network-suricata", "agent_group": "network-sensor", "description": "Suricata",
            "rule_groups": ["suricata"], "max_silence_hours": 24}]


class Api:
    def __init__(self, agents):
        self.agents, self.calls = agents, []

    def affected_items(self, path, params=None):
        return self.agents

    def request(self, method, path, **kw):
        self.calls.append((method, path))
        return {}


class Indexer:
    def __init__(self, latest=None, error=None):
        self.latest, self.error, self.bodies = latest, error, []

    def request(self, method, path, json=None, **kw):
        self.bodies.append(json)
        if self.error:
            raise self.error
        return {"hits": {"hits": [{"_source": {"timestamp": self.latest}}] if self.latest else []}}


def agent(name="lnx", status="active", groups=("default", "linux"), aid="001"):
    return {"id": aid, "name": name, "status": status, "group": list(groups)}


def test_repository_sources_are_valid():
    ids = {s["id"] for s in telemetry.load_sources(ROOT)}
    assert {"linux-fim", "windows-sysmon", "windows-security", "network-suricata"} <= ids


def test_recent_event_passes_and_query_is_scoped_to_agent_and_groups():
    idx = Indexer(latest=(NOW - timedelta(hours=2)).isoformat())
    results = telemetry.check_sources(Api([agent()]), idx, SOURCES[:1], NOW)
    assert [(r.name, r.status) for r in results] == [("linux-fim@lnx", PASS)]
    filters = idx.bodies[0]["query"]["bool"]["filter"]
    assert {"term": {"agent.id": "001"}} in filters and {"terms": {"rule.groups": ["syscheck"]}} in filters


def test_silent_source_is_a_warning_not_a_pass():
    results = telemetry.check_sources(Api([agent()]), Indexer(), SOURCES[:1], NOW)
    assert results[0].status == WARNING and "not proof" in results[0].detail


def test_undeployed_source_and_disconnected_agent():
    results = telemetry.check_sources(Api([agent(status="disconnected")]), Indexer(), SOURCES, NOW)
    assert [r.status for r in results] == [WARNING, NOT_VERIFIED]
    assert "not deployed" in results[1].detail


def test_indexer_error_fails_only_that_check():
    results = telemetry.check_sources(Api([agent()]), Indexer(error=ServiceError("boom", 500)), SOURCES[:1], NOW)
    assert results[0].status == FAIL


@pytest.mark.parametrize("text,match", [
    ("sources: []", "non-empty"),
    ("sources: [{id: a, agent_group: linux, description: d, rule_groups: [x], max_silence_hours: 0}]", "max_silence"),
    ("sources: [{id: a, agent_group: linux, description: d, rule_groups: ['a b'], max_silence_hours: 1}]", "rule_groups"),
    ("sources: [{id: A!, agent_group: linux, description: d, rule_groups: [x], max_silence_hours: 1}]", "invalid"),
    ("sources: [", "invalid YAML"),
])
def test_invalid_sources_rejected(tmp_path, text, match):
    path = telemetry.sources_file(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text(text)
    with pytest.raises(telemetry.TelemetryError, match=match):
        telemetry.load_sources(tmp_path)


def test_assign_group_adds_once_and_keeps_existing_groups():
    api = Api([agent()])
    assert assign_group(api, "lnx", "network-sensor", {"linux", "network-sensor"}) == "001"
    assert api.calls == [("PUT", "/agents/001/group/network-sensor")]
    api = Api([agent(groups=("linux", "network-sensor"))])
    assign_group(api, "lnx", "network-sensor", {"network-sensor"})
    assert api.calls == []


@pytest.mark.parametrize("agents,group,match", [
    ([agent()], "nope", "unknown group"),
    ([], "network-sensor", "found 0"),
    ([agent(aid="001"), agent(aid="002")], "network-sensor", "found 2"),
])
def test_assign_group_refuses_ambiguous_targets(agents, group, match):
    with pytest.raises(AgentConfigError, match=match):
        assign_group(Api(agents), "lnx", group, {"network-sensor"})
