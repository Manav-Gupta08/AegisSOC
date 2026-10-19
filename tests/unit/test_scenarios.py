"""Scenario runner tests. All endpoint commands and alerts are SYNTHETIC stand-ins; no simulation runs."""
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from aegissoc import scenarios
from aegissoc.scenarios import (
    CLEANUP_REQUIRED, FAILED, INCONCLUSIVE, PASSED, SKIPPED, TIMED_OUT, Clock, ScenarioError,
    classify, load_scenarios, run_scenario, validate_scenario, wsl_argv,
)

ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)

BASE = {
    "id": "LNX-900", "title": "t", "technique": "T1098", "platform": "linux", "description": "d",
    "target": {"agent_group": "linux", "wsl_distro": "Ubuntu"}, "safety": ["s"],
    "execute": {"run_as": "root", "argv": ["groupadd", "x"]},
    "expected": {"detection_rules": ["100202"]}, "timeout_seconds": 30,
    "cleanup": [{"run_as": "root", "argv": ["groupdel", "x"]}],
    "verify_cleanup": {"run_as": "root", "argv": ["sh", "-c", "true"]},
}


def scenario(tmp_path: Path, **overrides) -> dict:
    data = {**BASE, **overrides}
    path = tmp_path / f"{data['id']}-test.yml"
    path.write_text(yaml.safe_dump(data))
    return validate_scenario(dict(data), path)


def test_repository_scenarios_are_valid():
    loaded = load_scenarios(ROOT)
    assert {"LNX-001", "LNX-002", "LNX-003", "LNX-004", "LNX-005"} <= set(loaded)


@pytest.mark.parametrize("overrides,match", [
    ({"id": "BAD-1"}, "invalid id"),
    ({"technique": "1098"}, "technique"),
    ({"platform": "windows"}, "only platform"),
    ({"execute": {"run_as": "admin", "argv": ["x"]}}, "run_as"),
    ({"execute": {"run_as": "root", "argv": "groupadd x"}}, "list of strings"),
    ({"verify_cleanup": None}, "verify_cleanup"),
    ({"expected": {"telemetry_rules": ["5557"]}}, "detection_rules or forbidden_rules"),
    ({"expected": {"forbidden_rules": ["100100"]}}, "observe_full_window"),
    ({"timeout_seconds": 5000}, "timeout_seconds"),
    ({"target": {"agent_group": "linux", "wsl_distro": "Ubuntu; rm -rf /"}}, "wsl_distro"),
])
def test_invalid_scenarios_rejected(tmp_path, overrides, match):
    with pytest.raises(ScenarioError, match=match):
        scenario(tmp_path, **overrides)


def test_wsl_argv_has_no_shell_and_respects_user():
    root_cmd = wsl_argv("Ubuntu", {"run_as": "root", "argv": ["groupadd", "x"]})
    assert root_cmd == ["wsl", "-d", "Ubuntu", "-u", "root", "--", "groupadd", "x"]
    assert "-u" not in wsl_argv("Ubuntu", {"run_as": "default", "argv": ["id"]})


@pytest.mark.parametrize("expected,observed,had,status", [
    ({"detection_rules": ["100100"], "telemetry_rules": ["5557"]}, {"5557", "100100"}, True, PASSED),
    ({"detection_rules": ["100100"], "telemetry_rules": ["5557"]}, {"5557"}, True, FAILED),
    ({"detection_rules": ["100100"], "telemetry_rules": ["5557"]}, set(), False, INCONCLUSIVE),
    ({"detection_rules": ["100100"], "telemetry_rules": ["5557"]}, set(), True, INCONCLUSIVE),
    ({"detection_rules": ["100202"]}, set(), True, TIMED_OUT),
    ({"detection_rules": ["100202"]}, set(), False, INCONCLUSIVE),
    ({"forbidden_rules": ["100100"], "telemetry_rules": ["5557"]}, {"5557"}, True, PASSED),
    ({"forbidden_rules": ["100100"], "telemetry_rules": ["5557"]}, {"5557", "100100"}, True, FAILED),
    ({"forbidden_rules": ["100100"], "telemetry_rules": ["5557"]}, set(), False, INCONCLUSIVE),
])
def test_classify(expected, observed, had, status):
    assert classify(expected, observed, had)[0] == status


class FakeClock(Clock):
    def __init__(self):
        self.t = T0
        super().__init__(now=lambda: self.t, sleep=self._sleep)

    def _sleep(self, s):
        self.t += timedelta(seconds=s)


class Api:
    def __init__(self, status="active", groups=("default", "linux"), count=1):
        self.agents = [{"id": f"00{i + 1}", "name": f"a{i}", "status": status, "group": list(groups), "version": "v"} for i in range(count)]

    def affected_items(self, path, params=None):
        return self.agents


class Indexer:
    """Returns the given alerts only after `appear_after` seconds of simulated time."""

    def __init__(self, clock, alerts, appear_after=10):
        self.clock, self.alerts, self.appear_after = clock, alerts, appear_after

    def request(self, method, path, **kwargs):
        visible = self.clock.t >= T0 + timedelta(seconds=self.appear_after)
        filt = kwargs["json"]["query"]["bool"]["filter"]
        ids = next((f["terms"]["rule.id"] for f in filt if "terms" in f and "rule.id" in f["terms"]), None)
        hits = [a for a in self.alerts if visible and (ids is None or a["id"] in ids)]
        return {"hits": {"hits": [{"_source": {"timestamp": (T0 + timedelta(seconds=2)).isoformat(),
                                               "rule": {"id": a["id"], "level": 8}}} for a in hits]}}


def recorder(fail_on=()):
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        rc = 1 if any(token in cmd for token in fail_on) else 0
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")
    return run, calls


def test_run_passes_on_observed_alert_and_cleans_up(tmp_path):
    clock = FakeClock()
    run, calls = recorder()
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, [{"id": "100202"}]), run=run, clock=clock, log=lambda m: None)
    assert r.status == PASSED and r.cleanup == "verified" and r.first_detection_latency_s == 2.0
    assert calls[-2][-2:] == ["groupdel", "x"]


def test_exit_code_success_alone_never_passes(tmp_path):
    clock = FakeClock()
    run, _ = recorder()
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, []), run=run, clock=clock, log=lambda m: None)
    assert r.execute_exit_code == 0 and r.status == INCONCLUSIVE


def test_cleanup_failure_marks_cleanup_required(tmp_path):
    clock = FakeClock()
    run, _ = recorder(fail_on=("groupdel",))
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, [{"id": "100202"}]), run=run, clock=clock, log=lambda m: None)
    assert r.status == CLEANUP_REQUIRED and r.cleanup == "FAILED" and "PASSED" in r.reason


def test_cleanup_runs_even_if_execution_raises(tmp_path):
    clock = FakeClock()
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[-2:] == ["groupadd", "x"]:
            raise subprocess.TimeoutExpired(cmd, 120)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with pytest.raises(subprocess.TimeoutExpired):
        run_scenario(scenario(tmp_path), Api(), Indexer(clock, []), run=run, clock=clock, log=lambda m: None)
    assert any(c[-2:] == ["groupdel", "x"] for c in calls)


@pytest.mark.parametrize("api,reason", [
    (Api(status="disconnected"), "disconnected"),
    (Api(groups=("default",)), "no agent"),
    (Api(count=2), "ambiguous"),
])
def test_skipped_when_target_not_ready(tmp_path, api, reason):
    clock = FakeClock()
    run, calls = recorder()
    r = run_scenario(scenario(tmp_path), api, Indexer(clock, []), run=run, clock=clock, log=lambda m: None)
    assert r.status == SKIPPED and reason in r.reason and calls == []


def test_skipped_when_prerequisite_fails(tmp_path):
    clock = FakeClock()
    run, calls = recorder(fail_on=("precheck",))
    sc = scenario(tmp_path, prerequisites=[{"name": "p", "run_as": "root", "argv": ["precheck"]}])
    r = run_scenario(sc, Api(), Indexer(clock, []), run=run, clock=clock, log=lambda m: None)
    assert r.status == SKIPPED and "prerequisite" in r.reason
    assert not any("groupadd" in c for c in calls), "must not execute after a failed prerequisite"


def test_negative_scenario_observes_full_window(tmp_path):
    clock = FakeClock()
    run, _ = recorder()
    sc = scenario(tmp_path, expected={"forbidden_rules": ["100100"], "telemetry_rules": ["5557"]},
                  observe_full_window=True, cleanup=[], verify_cleanup=None)
    r = run_scenario(sc, Api(), Indexer(clock, [{"id": "5557"}]), run=run, clock=clock, log=lambda m: None)
    assert r.status == PASSED and clock.t >= T0 + timedelta(seconds=30)
