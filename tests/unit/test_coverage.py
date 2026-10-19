from pathlib import Path

from aegissoc.coverage import build_matrix, render_markdown

ROOT = Path(__file__).resolve().parents[2]


def report(**statuses):
    return {"generated_at": "2026-10-13T12:00:00+00:00",
            "results": [{"scenario_id": k, "status": v, "first_detection_latency_s": 1.5} for k, v in statuses.items()]}


def rows_by_id(matrix):
    return {r["rule_id"]: r for r in matrix["rows"]}


def test_matrix_without_report_claims_no_observation():
    rows = rows_by_id(build_matrix(ROOT, None))
    assert all(not r["observed_in_lab"] and r["scenario_results"] == {} for r in rows.values())
    assert rows[100100]["negative_scenarios"] == ["LNX-002"]


def test_only_passed_positive_scenarios_count_as_observed():
    rows = rows_by_id(build_matrix(ROOT, report(**{"LNX-001": "FAILED", "LNX-003": "PASSED"})))
    assert rows[100100]["observed_in_lab"] is False
    assert rows[100200]["observed_in_lab"] is True and rows[100200]["min_latency_s"] == 1.5


def test_negative_pass_is_not_an_observation():
    rows = rows_by_id(build_matrix(ROOT, report(**{"LNX-002": "PASSED"})))
    assert rows[100100]["observed_in_lab"] is False
    assert rows[100100]["scenario_results"] == {"LNX-002": "PASSED"}


def test_markdown_escapes_table_breaking_text():
    matrix = {"generated_at": "x", "scenario_report_generated_at": None, "rows": [{
        "rule_id": 1, "title": "a|b<script>", "techniques": ["T1"], "rule_status": "tested", "logtest_cases": 0,
        "positive_scenarios": [], "negative_scenarios": [], "scenario_results": {}, "observed_in_lab": False,
        "min_latency_s": None, "limitations": ["x|y"]}]}
    md = render_markdown(matrix)
    assert "a\\|b&lt;script&gt;" in md and "<script>" not in md
