"""Metric calculation tests on SYNTHETIC report fixtures."""
import json
import subprocess

from aegissoc import metrics


def rep(at, *results):
    return {"generated_at": at, "results": [{"scenario_id": s, "status": st, "first_detection_latency_s": lat}
                                            for s, st, lat in results]}


def test_scenario_metrics_pass_rate_latency_and_regressions():
    reports = [
        rep("2026-10-13T10:00", ("LNX-001", "PASSED", 10.0), ("LNX-003", "PASSED", 1.0)),
        rep("2026-10-14T10:00", ("LNX-001", "FAILED", None), ("LNX-003", "PASSED", 0.5), ("LNX-009", "SKIPPED", None)),
    ]
    m = metrics.scenario_metrics(reports)
    assert m["latest_executed"] == 2 and m["latest_pass_rate"] == 0.5
    assert m["latest_failures"] == ["LNX-001"] and m["regressions"] == ["LNX-001"] and m["regression_rate"] == 0.5
    assert m["trigger_to_alert_latency_s"] == {"samples": 3, "median": 1.0, "max": 10.0}


def test_skipped_runs_do_not_count_as_executed():
    m = metrics.scenario_metrics([rep("t", ("LNX-001", "SKIPPED", None))])
    assert m["latest_executed"] == 0 and m["latest_pass_rate"] is None


def test_load_reports_deduplicates_across_folders(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(), b.mkdir()
    for folder in (a, b):
        (folder / "scenarios-1.json").write_text(json.dumps(rep("2026-10-13T10:00", ("LNX-001", "PASSED", 1.0))))
    (b / "scenarios-2.json").write_text(json.dumps(rep("2026-10-14T10:00", ("LNX-001", "PASSED", 2.0))))
    loaded = metrics.load_reports([a, b], "scenarios-*.json")
    assert [r["generated_at"] for r in loaded] == ["2026-10-13T10:00", "2026-10-14T10:00"]


def test_availability_from_health_reports():
    reports = [{"generated_at": f"t{i}", "overall": o, "checks": [{"name": "agents", "status": s}]}
               for i, (s, o) in enumerate([("PASS", "PASS"), ("WARNING", "WARNING"), ("NOT_VERIFIED", "FAIL"), ("PASS", "PASS")])]
    m = metrics.availability_metrics(reports)
    assert m["health_samples"] == 4 and m["agents_all_active_ratio"] == 0.5 and m["overall_fail_samples"] == 1


def test_case_metrics_resolution_time():
    def case(created, closed_at, cls, status="closed"):
        audit = [{"action": "created", "at": created, "detail": {}}]
        if closed_at:
            audit.append({"action": "transition", "at": closed_at, "detail": {"to": status}})
        return {"created_at": created, "status": status if closed_at else "triage", "classification": cls, "audit": audit}

    m = metrics.case_metrics([
        case("2026-10-14T10:00:00+00:00", "2026-10-14T10:30:00+00:00", "test_activity"),
        case("2026-10-14T10:00:00+00:00", "2026-10-14T11:30:00+00:00", "false_positive", "false_positive"),
        case("2026-10-14T10:00:00+00:00", None, "unclassified"),
    ])
    assert m["closed"] == 2 and m["open"] == 1 and m["resolution_minutes"] == {"median": 60.0, "max": 90.0}
    assert m["analyst_labelled_false_positives"] == 1


def test_parse_docker_stats():
    line = json.dumps({"Name": "aegissoc-wazuh.indexer-1", "CPUPerc": "1.93%", "MemUsage": "1.587GiB / 2.5GiB", "MemPerc": "63.48%"})
    assert metrics.parse_docker_stats(line) == [{"name": "aegissoc-wazuh.indexer-1", "cpu_percent": 1.93,
                                                  "mem_usage": "1.587GiB", "mem_limit": "2.5GiB", "mem_percent": 63.48}]


def test_resources_empty_when_docker_unavailable():
    fail = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "error")  # noqa: E731
    assert metrics.resources("aegissoc", run=fail) == []


def test_storage_upper_bound_per_alert():
    class Idx:
        def request(self, method, path, **kw):
            return [{"node": "n", "disk.indices": "1000000", "disk.percent": "7", "disk.avail": "5000"}]

    s = metrics.storage(Idx(), 500)
    assert s["indices_bytes"] == 1000000 and s["bytes_per_alert_upper_bound"] == 2000 and s["disk_percent"] == 7


def test_markdown_escapes_alert_derived_text():
    # Rule descriptions interpolate decoded fields (e.g. $(srcuser)), so they are attacker-influenced.
    m = {
        "generated_at": "t", "resources": [],
        "scenarios": metrics.scenario_metrics([]),
        "availability": metrics.availability_metrics([]),
        "cases": metrics.case_metrics([]),
        "storage": {"indices_bytes": None, "disk_percent": None, "bytes_per_alert_upper_bound": None},
        "alert_volume": {"window_days": 7, "total": 1, "aegissoc_rule_alerts": 1, "per_day": {}, "by_level": {},
                         "per_agent": {"<b>agent</b>": 1},
                         "top_rules": [{"rule_id": "100100", "count": 1,
                                        "description": "failures for user <img src=x onerror=alert(1)>|x\nrow"}]},
    }
    out = metrics.render_markdown(m)
    assert "<img" not in out and "<b>" not in out and "&lt;img" in out and "\\|x row" in out
