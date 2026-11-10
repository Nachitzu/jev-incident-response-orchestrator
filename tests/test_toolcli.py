"""Tests for `soar-tool`, the deterministic plumbing behind the console (no-API) mode.

These exercise every subcommand offline: validation (pass and fail), the offline
threat-intel and ATT&CK lookups, playbook selection, and report rendering. No network,
no API key — same guarantee as the rest of the suite.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.orchestrator.schemas import CaseReport, Incident, Investigation, ResponsePlan
from src.orchestrator.toolcli import main


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, dict]:
    rc = main(argv)
    out = capsys.readouterr().out.strip()
    payload = json.loads(out) if out else {}
    return rc, payload


# --- validate ----------------------------------------------------------------
def test_validate_ok(incident: Incident, tmp_path: Path, capsys) -> None:
    p = tmp_path / "incident.json"
    p.write_text(incident.model_dump_json(), encoding="utf-8")
    rc, payload = _run(["validate", "--schema", "incident", "--in", str(p)], capsys)
    assert rc == 0
    assert payload["status"] == "ok"
    assert payload["normalized"]["incident_id"] == "inc-0001"


def test_validate_rejects_business_rule_violation(tmp_path: Path, capsys) -> None:
    # HIGH severity with sub-0.5 confidence is rejected by the Incident validator.
    bad = {
        "incident_id": "x",
        "created_at": "2026-07-08T00:00:00Z",
        "triggering_events": ["e1"],
        "title": "t",
        "category": "malware",
        "severity": "HIGH",
        "detection_confidence": 0.2,
        "rationale": "r",
    }
    p = tmp_path / "bad.json"
    p.write_text(json.dumps(bad), encoding="utf-8")
    rc = main(["validate", "--schema", "incident", "--in", str(p)])
    assert rc == 1
    assert "detection_confidence" in capsys.readouterr().err


# --- intel -------------------------------------------------------------------
def test_intel_known_indicator(capsys) -> None:
    rc, payload = _run(["intel", "45.133.1.77", "--type", "ip"], capsys)
    assert rc == 0
    assert payload["status"] == "ok"
    assert payload["reputation"] == "malicious"
    assert payload["source"] == "local_intel"


def test_intel_unknown_indicator(capsys) -> None:
    rc, payload = _run(["intel", "8.8.8.8", "--type", "ip"], capsys)
    assert rc == 0
    assert payload["status"] == "unknown"
    assert payload["reputation"] == "unknown"


# --- attack ------------------------------------------------------------------
def test_attack_verify_hit(capsys) -> None:
    rc, payload = _run(["attack", "verify", "T1566"], capsys)
    assert rc == 0
    assert payload["status"] == "ok"
    assert payload["technique"]["name"] == "Phishing"


def test_attack_verify_miss(capsys) -> None:
    rc, payload = _run(["attack", "verify", "T9999"], capsys)
    assert rc == 0
    assert payload["status"] == "not_found"


def test_attack_search(capsys) -> None:
    rc, payload = _run(["attack", "search", "phishing"], capsys)
    assert rc == 0
    assert any(m["technique_id"] == "T1566" for m in payload["matches"])


# --- playbook ----------------------------------------------------------------
def test_playbook_known_category(capsys) -> None:
    rc, payload = _run(["playbook", "phishing"], capsys)
    assert rc == 0
    assert payload["category"] == "phishing"
    assert len(payload["steps"]) >= 1


def test_playbook_unknown_category(capsys) -> None:
    rc = main(["playbook", "does_not_exist"])
    assert rc == 1
    assert "no playbook" in capsys.readouterr().err


# --- report ------------------------------------------------------------------
def test_report_renders_markdown_and_json(
    incident: Incident,
    investigation: Investigation,
    response_plan: ResponsePlan,
    audit_entry,
    tmp_path: Path,
    capsys,
) -> None:
    report = CaseReport(
        incident_id="inc-0001",
        incident=incident,
        investigation=investigation,
        response_plan=response_plan,
        final_state="escalated_to_human",
        audit_log=[audit_entry],
        generated_at="2026-07-08T03:30:00Z",
    )
    case_path = tmp_path / "case.json"
    case_path.write_text(report.model_dump_json(), encoding="utf-8")

    rc, payload = _run(
        ["report", "--case", str(case_path), "--out", str(tmp_path / "reports")],
        capsys,
    )
    assert rc == 0
    md = Path(payload["markdown"])
    js = Path(payload["json"])
    assert md.exists() and js.exists()
    body = md.read_text(encoding="utf-8")
    assert "inc-0001" in body
    assert "Response plan" in body
    assert "human approval required" in body
