"""Health check logic tests. Inputs are SYNTHETIC response shapes, not real lab telemetry."""
from datetime import datetime, timedelta, timezone

import pytest

from aegissoc import health
from aegissoc.clients import ServiceError
from aegissoc.health import (
    FAIL, NOT_VERIFIED, PASS, WARNING, CheckResult,
    check_agents, check_alert_freshness, check_containers, check_default_credentials,
    check_indexer_cluster, check_indexer_disk, check_manager_daemons, check_port_exposure,
    overall_status, parse_compose_ps, parse_timestamp,
)

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)


class FakeApi:
    def __init__(self, responses):
        self.responses = responses

    def affected_items(self, path, params=None):
        return self.responses[path]


class FakeIndexer:
    def __init__(self, responses=None, error=None):
        self.responses, self.error = responses or {}, error

    def request(self, method, path, **kwargs):
        if self.error:
            raise self.error
        return self.responses[path]


def _row(service, state="running", health="healthy", pubs=()):
    return {"Service": service, "State": state, "Health": health,
            "Publishers": [{"URL": u, "TargetPort": t, "PublishedPort": p} for u, t, p in pubs]}


def test_parse_compose_ps_handles_ndjson_and_array():
    assert parse_compose_ps('{"Service":"a"}\n{"Service":"b"}\n') == [{"Service": "a"}, {"Service": "b"}]
    assert parse_compose_ps('[{"Service":"a"}]') == [{"Service": "a"}]
    assert parse_compose_ps("") == []


def test_containers_pass_and_missing():
    rows = [_row(s) for s in health.EXPECTED_SERVICES]
    assert check_containers(rows).status == PASS
    assert check_containers(rows[:2]).status == FAIL
    assert check_containers([*rows[:2], _row("wazuh.dashboard", state="exited")]).status == FAIL


def test_port_exposure_detects_wildcard_bind():
    rows = [_row("wazuh.indexer", pubs=[("0.0.0.0", 9200, 9200)])]
    result = check_port_exposure(rows, "127.0.0.1")
    assert result.status == FAIL and "9200" in result.detail


def test_port_exposure_allows_agent_bind_only_for_agent_ports():
    rows = [_row("wazuh.manager", pubs=[("10.77.0.1", 1514, 1514), ("10.77.0.1", 55000, 55000)])]
    result = check_port_exposure(rows, "10.77.0.1")
    assert result.status == FAIL and "55000" in result.detail
    ok = [_row("wazuh.manager", pubs=[("10.77.0.1", 1514, 1514), ("127.0.0.1", 55000, 55000)])]
    assert check_port_exposure(ok, "10.77.0.1").status == PASS


def test_port_exposure_without_bindings_is_not_verified():
    assert check_port_exposure([], "127.0.0.1").status == NOT_VERIFIED


def test_manager_daemons():
    running = {d: "running" for d in health.REQUIRED_DAEMONS}
    assert check_manager_daemons(FakeApi({"/manager/status": [running]})).status == PASS
    stopped = {**running, "wazuh-analysisd": "stopped"}
    result = check_manager_daemons(FakeApi({"/manager/status": [stopped]}))
    assert result.status == FAIL and "wazuh-analysisd" in result.detail


def test_agents_states():
    manager_only = [{"id": "000", "name": "wazuh.manager", "status": "active"}]
    assert check_agents(FakeApi({"/agents": manager_only})).status == WARNING
    mixed = manager_only + [{"id": "001", "name": "lnx", "status": "active"}, {"id": "002", "name": "win", "status": "disconnected"}]
    result = check_agents(FakeApi({"/agents": mixed}))
    assert result.status == WARNING and "win" in result.detail
    assert check_agents(FakeApi({"/agents": mixed[:2]})).status == PASS
    drift = manager_only + [{"id": "001", "name": "lnx", "status": "active", "group_config_status": "not synced"}]
    result = check_agents(FakeApi({"/agents": drift}))
    assert result.status == WARNING and "drift" in result.detail


@pytest.mark.parametrize("status,expected", [("green", PASS), ("yellow", WARNING), ("red", FAIL), (None, FAIL)])
def test_indexer_cluster(status, expected):
    assert check_indexer_cluster(FakeIndexer({"/_cluster/health": {"status": status}})).status == expected


@pytest.mark.parametrize("pct,expected", [("40", PASS), ("75", WARNING), ("85", FAIL)])
def test_indexer_disk_thresholds(pct, expected):
    idx = FakeIndexer({"/_cat/allocation": [{"node": "n1", "disk.percent": pct}]})
    assert check_indexer_disk(idx, 75, 85).status == expected


def test_indexer_disk_without_data_is_not_verified():
    assert check_indexer_disk(FakeIndexer({"/_cat/allocation": [{"node": "UNASSIGNED"}]}), 75, 85).status == NOT_VERIFIED


@pytest.mark.parametrize("value", ["2026-10-13T11:55:00.123+0000", "2026-10-13T11:55:00.123Z", "2026-10-13T11:55:00"])
def test_parse_timestamp_formats(value):
    assert parse_timestamp(value).tzinfo is not None


def _alerts(ts):
    return FakeIndexer({"/wazuh-alerts-*/_search": {"hits": {"hits": [{"_source": {"timestamp": ts}}]}}})


def test_alert_freshness_pass_and_stale():
    assert check_alert_freshness(_alerts((NOW - timedelta(minutes=5)).isoformat()), 60, NOW).status == PASS
    stale = check_alert_freshness(_alerts((NOW - timedelta(minutes=90)).isoformat()), 60, NOW)
    assert stale.status == WARNING and "stalled" in stale.detail


def test_alert_freshness_missing_data_is_warning_not_pass():
    empty = FakeIndexer({"/wazuh-alerts-*/_search": {"hits": {"hits": []}}})
    assert check_alert_freshness(empty, 60, NOW).status == WARNING
    missing_index = FakeIndexer(error=ServiceError("not found", 404))
    assert check_alert_freshness(missing_index, 60, NOW).status == WARNING


def test_alert_freshness_propagates_auth_errors():
    with pytest.raises(ServiceError):
        check_alert_freshness(FakeIndexer(error=ServiceError("forbidden", 403)), 60, NOW)


def test_default_credentials():
    assert check_default_credentials(lambda u, p: False, lambda u, p: False).status == PASS
    result = check_default_credentials(lambda u, p: u == "wazuh", lambda u, p: False)
    assert result.status == FAIL and "api:wazuh" in result.detail


def test_overall_status_precedence():
    mk = lambda s: CheckResult("x", s, "")  # noqa: E731
    assert overall_status([mk(PASS)]) == PASS
    assert overall_status([mk(PASS), mk(NOT_VERIFIED)]) == WARNING
    assert overall_status([mk(WARNING), mk(FAIL)]) == FAIL
    assert overall_status([]) == WARNING


def test_build_report_redacts_secrets(ctx):
    secret = ctx.secret("INDEXER_READER_PASSWORD")
    results = [CheckResult("x", FAIL, f"error contained {secret}")]
    report = health.build_report(ctx, results, NOW)
    assert secret not in str(report)
    assert report["overall"] == FAIL and report["wazuh_version"] == "4.14.8"


def test_write_report(ctx, tmp_path):
    report = health.build_report(ctx, [CheckResult("x", PASS, "ok")], NOW)
    path = health.write_report(report, tmp_path)
    assert path.name == "health-20261013T120000+0000.json" and path.read_text().startswith("{")
