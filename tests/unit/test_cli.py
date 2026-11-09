import pytest

from aegissoc import cli


@pytest.mark.parametrize("arguments, expected", [
    (["detections", "validate"], "rule(s)"),
    (["agent-config", "validate"], "valid: linux, network-sensor, windows"),
    (["scenarios", "validate"], "scenario(s)"),
    (["playbooks", "validate"], "playbook(s)"),
    (["telemetry", "--validate"], "source(s)"),
])
def test_offline_validation_commands(arguments, expected, capsys):
    assert cli.main(arguments) == 0
    assert expected in capsys.readouterr().out


@pytest.mark.parametrize("arguments, expected", [
    (["scenarios", "run", "LNX-001"], "without --authorize"),
    (["scenarios", "run", "LNX-999", "--authorize"], "unknown"),
    (["scenarios", "run", "--authorize"], "specify scenario ids or --all"),
])
def test_scenario_cli_rejects_unsafe_requests_before_loading_context(arguments, expected, monkeypatch, capsys):
    monkeypatch.setattr(cli.Context, "load", lambda *args, **kwargs: pytest.fail("must not load live context"))
    assert cli.main(arguments) == 2
    assert expected in capsys.readouterr().err


def test_case_cli_offline_workflow(tmp_path, monkeypatch, capsys):
    store = cli.cases.CaseStore(tmp_path)
    monkeypatch.setattr(cli.case_cli, "_store", lambda: store)
    assert cli.main(["case", "new", "--title", "Test incident", "--severity", "high", "--actor", "alice"]) == 0
    case_id = store.list()[0]["case_id"]
    assert cli.main(["case", "transition", case_id, "triage"]) == 0
    assert cli.main(["case", "note", case_id, "Investigating"]) == 0
    assert cli.main(["case", "show", case_id]) == 0
    assert cli.main(["case", "verify", case_id]) == 0
    report = tmp_path / "report.md"
    assert cli.main(["case", "report", case_id, "--output", str(report)]) == 0
    assert "Investigating" in report.read_text(encoding="utf-8")
    assert report.with_suffix(".json").is_file()
    assert cli.main(["case", "execute", case_id, "ACT-001"]) == 2
    assert "only --simulate" in capsys.readouterr().err