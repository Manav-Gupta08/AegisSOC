import shutil
import subprocess
from pathlib import Path

import pytest

from aegissoc import detections
from aegissoc.detections import DetectionError, evaluate_case, run_logtest_case, validate

ROOT = Path(__file__).resolve().parents[2]

RULE = """<group name="aegissoc,">
  <rule id="{id}" level="{level}">
    <if_sid>5557</if_sid>
    <description>{desc}</description>
  </rule>
</group>
"""

META = """id: {id}
title: t
status: {status}
level: {level}
rule_file: detections/wazuh/rules/aegissoc_test.xml
rationale: r
telemetry: [journald]
mitre: [{mitre}]
false_positives: [f]
limitations: [l]
investigation: [i]
tests:
  logtest:
    - name: positive
      events: ["x"]
      expect_last: {id}
"""


def make_repo(tmp_path: Path, rid=100150, level=7, status="experimental", mitre="T1110", desc="d", meta_id=None) -> Path:
    rules = tmp_path / "detections" / "wazuh" / "rules"
    meta = tmp_path / "detections" / "metadata"
    rules.mkdir(parents=True)
    meta.mkdir(parents=True)
    (rules / "aegissoc_test.xml").write_text(RULE.format(id=rid, level=level, desc=desc))
    mid = meta_id or rid
    (meta / f"{mid}.yml").write_text(META.format(id=mid, level=level, status=status, mitre=mitre))
    return tmp_path


def test_repository_detections_are_valid():
    ids = {r.id for r in validate(ROOT)}
    assert {100100, 100200, 100201, 100202} <= ids


def test_valid_minimal_repo(tmp_path):
    assert [r.id for r in validate(make_repo(tmp_path))] == [100150]


@pytest.mark.parametrize("kwargs,match", [
    ({"rid": 5600}, "outside the AegisSOC range"),
    ({"status": "done"}, "status"),
    ({"mitre": "X1110"}, "ATT&CK"),
    ({"desc": ""}, "no description"),
])
def test_invalid_detections_rejected(tmp_path, kwargs, match):
    with pytest.raises(DetectionError, match=match):
        validate(make_repo(tmp_path, **kwargs))


def test_missing_metadata_rejected(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "detections" / "metadata" / "100150.yml").unlink()
    with pytest.raises(DetectionError, match="no detections/metadata"):
        validate(repo)


def test_level_mismatch_rejected(tmp_path):
    repo = make_repo(tmp_path)
    meta = repo / "detections" / "metadata" / "100150.yml"
    meta.write_text(meta.read_text().replace("level: 7", "level: 12"))
    with pytest.raises(DetectionError, match="level"):
        validate(repo)


def test_duplicate_rule_ids_rejected(tmp_path):
    repo = make_repo(tmp_path)
    shutil.copy(repo / "detections/wazuh/rules/aegissoc_test.xml", repo / "detections/wazuh/rules/aegissoc_dup.xml")
    with pytest.raises(DetectionError, match="defined in both"):
        validate(repo)


def test_bad_rule_file_name_rejected(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "detections/wazuh/rules/aegissoc_test.xml").rename(repo / "detections/wazuh/rules/local_rules.xml")
    with pytest.raises(DetectionError, match="aegissoc_"):
        validate(repo)


def test_same_field_on_static_field_rejected(tmp_path):
    # Regression: rule 100100 used <same_field>srcuser</same_field> and never fired in logtest.
    repo = make_repo(tmp_path)
    rule = repo / "detections/wazuh/rules/aegissoc_test.xml"
    rule.write_text(rule.read_text().replace("<if_sid>5557</if_sid>", "<if_sid>5557</if_sid><same_field>srcuser</same_field>"))
    with pytest.raises(DetectionError, match="same_srcuser"):
        validate(repo)


def test_level_zero_requires_suppression_kind(tmp_path):
    repo = make_repo(tmp_path, rid=100950, level=0)
    with pytest.raises(DetectionError, match="kind: suppression"):
        validate(repo)


def test_suppression_must_use_suppression_range(tmp_path):
    repo = make_repo(tmp_path, rid=100150, level=0)
    meta = repo / "detections" / "metadata" / "100150.yml"
    meta.write_text("kind: suppression\n" + meta.read_text())
    with pytest.raises(DetectionError, match="100900-100999"):
        validate(repo)


def test_detection_requires_attack_mapping(tmp_path):
    repo = make_repo(tmp_path)
    meta = repo / "detections" / "metadata" / "100150.yml"
    meta.write_text(meta.read_text().replace("mitre: [T1110]", "mitre: []"))
    with pytest.raises(DetectionError, match="ATT&CK"):
        validate(repo)


def test_evaluate_expect_last_and_expect_none():
    assert evaluate_case(1, {"name": "p", "expect_last": 100100}, ["5557", "100100"]).status == "PASSED"
    assert evaluate_case(1, {"name": "p", "expect_last": 100100}, ["5557", "5557"]).status == "FAILED"
    assert evaluate_case(1, {"name": "n", "expect_none": [100100]}, ["5557"]).status == "PASSED"
    assert evaluate_case(1, {"name": "n", "expect_none": [100100]}, ["100100", "5557"]).status == "FAILED"


class LogtestApi:
    def __init__(self, ids):
        self.ids, self.calls = list(ids), []

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        if method == "DELETE":
            return {}
        return {"data": {"token": "tok", "output": {"rule": {"id": self.ids.pop(0)}}}}


def test_logtest_reuses_session_and_closes_it():
    api = LogtestApi(["5557", "100100"])
    assert run_logtest_case(api, {"events": ["a", "b"]}) == ["5557", "100100"]
    assert "token" not in api.calls[0][2]["json"] and api.calls[1][2]["json"]["token"] == "tok"
    assert api.calls[-1][:2] == ("DELETE", "/logtest/sessions/tok")


def test_deploy_refuses_uncommitted_detections(tmp_path):
    repo = make_repo(tmp_path)

    def fake_git(cmd, **kw):
        out = " M detections/wazuh/rules/aegissoc_test.xml\n" if "status" in cmd else "abc\n"
        return subprocess.CompletedProcess(cmd, 0, stdout=out, stderr="")

    with pytest.raises(DetectionError, match="uncommitted"):
        detections.deploy(repo, api=None, run=fake_git)


def test_deploy_uploads_validates_and_restarts(tmp_path):
    repo = make_repo(tmp_path)
    calls = []

    class Api:
        def request(self, method, path, **kwargs):
            calls.append((method, path))
            if path == "/manager/configuration/validation":
                return {"data": {"affected_items": [{"status": "OK"}]}}
            return {"data": {}}

    clean = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="" if "status" in cmd else "abc\n", stderr="")  # noqa: E731
    record = detections.deploy(repo, Api(), log=lambda m: None, run=clean)
    assert calls == [("PUT", "/rules/files/aegissoc_test.xml"), ("GET", "/manager/configuration/validation"), ("PUT", "/manager/restart")]
    assert record["git"] == {"commit": "abc", "detections_dirty": False}
    assert len(record["files"]["aegissoc_test.xml"]) == 64


def test_deploy_retries_validation_timeout_and_never_restarts_unvalidated(tmp_path):
    # Regression: validation returned HTTP 500 (API timeout) on 2026-10-14.
    from aegissoc.clients import ServiceError

    repo = make_repo(tmp_path)
    clean = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")  # noqa: E731

    def api_with(validation_failures):
        calls, remaining = [], [validation_failures]

        class Api:
            def request(self, method, path, **kwargs):
                calls.append(path)
                if path == "/manager/configuration/validation":
                    if remaining[0] > 0:
                        remaining[0] -= 1
                        raise ServiceError("timeout", 500)
                    return {"data": {"affected_items": [{"status": "OK"}]}}
                return {"data": {}}
        return Api(), calls

    api, calls = api_with(2)
    detections.deploy(repo, api, log=lambda m: None, run=clean, sleep=lambda s: None)
    assert calls.count("/manager/configuration/validation") == 3 and calls[-1] == "/manager/restart"

    api, calls = api_with(3)
    with pytest.raises(DetectionError, match="NOT restarted"):
        detections.deploy(repo, api, log=lambda m: None, run=clean, sleep=lambda s: None)
    assert "/manager/restart" not in calls


def test_deploy_does_not_restart_on_invalid_config(tmp_path):
    repo = make_repo(tmp_path)
    calls = []

    class Api:
        def request(self, method, path, **kwargs):
            calls.append(path)
            if path == "/manager/configuration/validation":
                return {"data": {"affected_items": [{"status": "KO", "details": ["bad rule"]}]}}
            return {"data": {}}

    clean = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")  # noqa: E731
    with pytest.raises(DetectionError, match="rejected"):
        detections.deploy(repo, Api(), log=lambda m: None, run=clean)
    assert "/manager/restart" not in calls
