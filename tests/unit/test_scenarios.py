"""Scenario runner tests. All endpoint commands and alerts are SYNTHETIC stand-ins; no simulation runs."""
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from aegissoc import scenarios
from aegissoc.scenarios import (
    CLEANUP_REQUIRED, FAILED, IDENTITY_COMMAND, INCONCLUSIVE, PASSED, SKIPPED, TIMED_OUT, Clock, Executor, ScenarioError,
    classify, default_executor, load_scenarios, run_scenario, validate_scenario,
)

ROOT = Path(__file__).resolve().parents[2]
T0 = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
WSL = Executor.parse("wsl:Ubuntu")

BASE = {
    "id": "LNX-900", "title": "t", "technique": "T1098", "platform": "linux", "description": "d",
    "target": {"agent_group": "linux"}, "safety": ["s"],
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
    ({"target": {"agent_group": "linux", "wsl_distro": "Ubuntu"}}, "AEGIS_LINUX_EXECUTOR"),
    ({"target": {"group": "linux"}}, "needs agent_group"),
])
def test_invalid_scenarios_rejected(tmp_path, overrides, match):
    with pytest.raises(ScenarioError, match=match):
        scenario(tmp_path, **overrides)


def test_wsl_executor_has_no_shell_and_respects_user():
    assert WSL.argv({"run_as": "root", "argv": ["groupadd", "x"]}) == ["wsl", "-d", "Ubuntu", "-u", "root", "--", "groupadd", "x"]
    assert WSL.argv({"run_as": "default", "argv": ["id"]}) == ["wsl", "-d", "Ubuntu", "--", "id"]


def test_local_executor_uses_non_interactive_sudo_for_root_only():
    local = Executor.parse("local")
    assert local.argv({"run_as": "root", "argv": ["groupadd", "x"]}) == ["sudo", "-n", "--", "groupadd", "x"]
    assert local.argv({"run_as": "default", "argv": ["id"]}) == ["id"]


@pytest.mark.parametrize("spec", ["", "ssh:host", "wsl:", "wsl:Ubuntu; rm -rf /", "wsl:Ubuntu --exec sh", "LOCAL"])
def test_invalid_executor_rejected(spec):
    with pytest.raises(ScenarioError, match="AEGIS_LINUX_EXECUTOR"):
        Executor.parse(spec)


def test_default_executor_per_host_platform():
    assert default_executor("win32") == "wsl:Ubuntu"
    assert default_executor("linux") == "local"


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


def is_identity(cmd):
    return cmd[-len(IDENTITY_COMMAND["argv"]):] == IDENTITY_COMMAND["argv"]


def recorder(fail_on=(), identity="001 a0"):
    """Records commands; the endpoint reports agent `identity` (Api() target is 001 a0)."""
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if is_identity(cmd):
            return subprocess.CompletedProcess(cmd, 0, stdout=f"{identity}\n", stderr="")
        rc = 1 if any(token in cmd for token in fail_on) else 0
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="")
    return run, calls


def test_run_passes_on_observed_alert_and_cleans_up(tmp_path):
    clock = FakeClock()
    run, calls = recorder()
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, [{"id": "100202"}]), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == PASSED and r.cleanup == "verified" and r.first_detection_latency_s == 2.0
    assert r.executor == "wsl:Ubuntu" and is_identity(calls[0])
    assert calls[-2][-2:] == ["groupdel", "x"]


@pytest.mark.parametrize("identity,reason", [("002 other", "reaches agent 002 other"), ("", "reaches agent unknown")])
def test_skipped_when_executor_reaches_a_different_endpoint(tmp_path, identity, reason):
    clock = FakeClock()
    run, calls = recorder(identity=identity)
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, []), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == SKIPPED and reason in r.reason
    assert len(calls) == 1, "nothing may run on an unconfirmed endpoint"


def test_skipped_with_sudo_hint_when_local_identity_unreadable(tmp_path):
    clock = FakeClock()
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, "", "sudo: a password is required")

    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, []), Executor.parse("local"), run=run, clock=clock,
                     log=lambda m: None)
    assert r.status == SKIPPED and "sudo -v" in r.reason and calls == [["sudo", "-n", "--", *IDENTITY_COMMAND["argv"]]]


def test_exit_code_success_alone_never_passes(tmp_path):
    clock = FakeClock()
    run, _ = recorder()
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, []), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.execute_exit_code == 0 and r.status == INCONCLUSIVE


def test_cleanup_failure_marks_cleanup_required(tmp_path):
    clock = FakeClock()
    run, _ = recorder(fail_on=("groupdel",))
    r = run_scenario(scenario(tmp_path), Api(), Indexer(clock, [{"id": "100202"}]), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == CLEANUP_REQUIRED and r.cleanup == "FAILED" and "PASSED" in r.reason


def test_failed_cleanup_step_does_not_stop_later_steps(tmp_path):
    clock = FakeClock()
    run, calls = recorder(fail_on=("first",))
    sc = scenario(tmp_path, cleanup=[{"run_as": "root", "argv": ["first"]}, {"run_as": "root", "argv": ["second"]}])
    r = run_scenario(sc, Api(), Indexer(clock, [{"id": "100202"}]), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == CLEANUP_REQUIRED and any(c[-1] == "second" for c in calls)


def test_cleanup_runs_even_if_execution_raises(tmp_path):
    clock = FakeClock()
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        if is_identity(cmd):
            return subprocess.CompletedProcess(cmd, 0, "001 a0\n", "")
        if cmd[-2:] == ["groupadd", "x"]:
            raise subprocess.TimeoutExpired(cmd, 120)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with pytest.raises(subprocess.TimeoutExpired):
        run_scenario(scenario(tmp_path), Api(), Indexer(clock, []), WSL, run=run, clock=clock, log=lambda m: None)
    assert any(c[-2:] == ["groupdel", "x"] for c in calls)


@pytest.mark.parametrize("api,reason", [
    (Api(status="disconnected"), "disconnected"),
    (Api(groups=("default",)), "no agent"),
    (Api(count=2), "ambiguous"),
])
def test_skipped_when_target_not_ready(tmp_path, api, reason):
    clock = FakeClock()
    run, calls = recorder()
    r = run_scenario(scenario(tmp_path), api, Indexer(clock, []), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == SKIPPED and reason in r.reason and calls == []


def test_skipped_when_prerequisite_fails(tmp_path):
    clock = FakeClock()
    run, calls = recorder(fail_on=("precheck",))
    sc = scenario(tmp_path, prerequisites=[{"name": "p", "run_as": "root", "argv": ["precheck"]}])
    r = run_scenario(sc, Api(), Indexer(clock, []), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == SKIPPED and "prerequisite" in r.reason
    assert not any("groupadd" in c for c in calls), "must not execute after a failed prerequisite"


def test_negative_scenario_observes_full_window(tmp_path):
    clock = FakeClock()
    run, _ = recorder()
    sc = scenario(tmp_path, expected={"forbidden_rules": ["100100"], "telemetry_rules": ["5557"]},
                  observe_full_window=True, cleanup=[], verify_cleanup=None)
    r = run_scenario(sc, Api(), Indexer(clock, [{"id": "5557"}]), WSL, run=run, clock=clock, log=lambda m: None)
    assert r.status == PASSED and clock.t >= T0 + timedelta(seconds=30)
