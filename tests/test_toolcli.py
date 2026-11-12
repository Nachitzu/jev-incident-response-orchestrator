"""`soar-tool`: exit codes and JSON output for the offline console plumbing."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from orchestrator.schemas import CaseReport
from orchestrator.toolcli import main

NOW = datetime(2026, 7, 8, 4, 0, tzinfo=UTC)


def _stdout_json(capsys) -> dict:
    return json.loads(capsys.readouterr().out)


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------
def test_validate_ok(tmp_path, capsys, incident):
    path = tmp_path / "incident.json"
    path.write_text(incident.model_dump_json(indent=2), encoding="utf-8")
    assert main(["validate", "--schema", "incident", "--in", str(path)]) == 0
    payload = _stdout_json(capsys)
    assert payload["status"] == "ok"
    assert payload["normalized"]["incident_id"] == "inc-0001"


def test_validate_failure_exits_one(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"incident_id": ""}', encoding="utf-8")
    assert main(["validate", "--schema", "incident", "--in", str(path)]) == 1
    captured = capsys.readouterr()
    assert "validation failed" in captured.err


def test_validate_unparseable_input_exits_one(tmp_path, capsys):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["validate", "--schema", "incident", "--in", str(path)]) == 1


# --------------------------------------------------------------------------
# intel / attack / playbook
# --------------------------------------------------------------------------
def test_intel_lookup(tmp_path, capsys):
    assert main(["intel", "185.220.101.34", "--type", "ip"]) == 0
    payload = _stdout_json(capsys)
    assert payload["status"] == "ok"
    assert payload["reputation"] == "malicious"


def test_attack_verify_and_search(capsys):
    assert main(["attack", "verify", "T1566"]) == 0
    assert _stdout_json(capsys)["status"] == "ok"
    assert main(["attack", "verify", "T9999"]) == 0
    assert _stdout_json(capsys)["status"] == "not_found"
    assert main(["attack", "search", "phishing"]) == 0
    assert _stdout_json(capsys)["matches"]


def test_playbook_found_and_missing(capsys):
    from orchestrator.tools import intel

    category = intel.playbook_categories()[0]
    assert main(["playbook", category]) == 0
    capsys.readouterr()
    assert main(["playbook", "cryptojacking"]) == 1
    assert "no playbook" in capsys.readouterr().err


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def _full_report(incident, investigation, response_plan) -> CaseReport:
    return CaseReport(
        incident_id="inc-0001",
        incident=incident,
        investigation=investigation,
        response_plan=response_plan,
        final_state="escalated_to_human",
        generated_at=NOW,
    )


def test_report_renders_files(tmp_path, capsys, incident, investigation, response_plan):
    report = _full_report(incident, investigation, response_plan)
    case_path = tmp_path / "case.json"
    case_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    out_dir = tmp_path / "reports"
    assert main(["report", "--case", str(case_path), "--out", str(out_dir)]) == 0
    payload = _stdout_json(capsys)
    assert payload["status"] == "ok"
    assert (out_dir / "inc-0001.md").exists()
    assert (out_dir / "inc-0001.json").exists()


def test_report_rejects_inconsistent_case(tmp_path, capsys, incident, investigation):
    broken = {
        "incident_id": "inc-0001",
        "incident": json.loads(incident.model_dump_json()),
        "investigation": json.loads(investigation.model_dump_json()),
        "final_state": "closed_false_positive",
        "generated_at": NOW.isoformat(),
    }
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(broken), encoding="utf-8")
    assert main(["report", "--case", str(case_path), "--out", str(tmp_path)]) == 1
    assert "invalid CaseReport" in capsys.readouterr().err


def test_report_blocks_path_traversal(
    tmp_path, capsys, incident, investigation, response_plan
):
    """A hostile incident_id must never write outside the output directory."""
    report = _full_report(incident, investigation, response_plan)
    hostile = json.loads(report.model_dump_json())
    hostile["incident_id"] = "../../escape"
    hostile["incident"]["incident_id"] = "../../escape"
    hostile["investigation"]["incident_id"] = "../../escape"
    hostile["response_plan"]["incident_id"] = "../../escape"
    case_path = tmp_path / "case.json"
    case_path.write_text(json.dumps(hostile), encoding="utf-8")
    out_dir = tmp_path / "reports"
    assert main(["report", "--case", str(case_path), "--out", str(out_dir)]) == 0
    capsys.readouterr()
    written = list(out_dir.iterdir())
    assert written, "the report should still be written"
    for path in written:
        assert path.resolve().parent == out_dir.resolve()
    assert not list(tmp_path.parent.glob("escape.*"))
