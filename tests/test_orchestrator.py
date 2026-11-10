"""The state machine end to end: both terminal paths, the audit log, the report."""

from __future__ import annotations

import json

import pytest

from src.orchestrator.orchestrator import OrchestratorError, load_events, run_case
from src.orchestrator.reporting import render_markdown, write_report
from tests.conftest import FakeClient, FakeToolbox
from tests.test_agents import DROP, ESCALATION, INVESTIGATION, PLAN

SAFE_PLAN = {
    **PLAN,
    "steps": [
        {
            "order": 1,
            "phase": "recovery",
            "action": "Open a ticket and monitor the account for 24h",
            "requires_approval": False,
            "automatable": True,
            "justification": "Observation only",
        }
    ],
    "requires_human_approval": False,
}


def _client(*payloads: dict) -> FakeClient:
    return FakeClient([json.dumps(p) for p in payloads])


def test_an_escalated_case_walks_the_full_pipeline(raw_event) -> None:
    client = _client(ESCALATION, INVESTIGATION, PLAN)
    report = run_case(
        [raw_event],
        client=client,
        investigator_toolbox=FakeToolbox(),
        responder_toolbox=FakeToolbox(),
    )
    assert report.final_state == "escalated_to_human"
    assert report.investigation is not None and report.response_plan is not None
    assert [e.stage for e in report.audit_log] == [
        "detection",
        "investigation",
        "response",
        "orchestration",
    ]


def test_a_plan_needing_no_approval_closes_the_case(raw_event) -> None:
    client = _client(ESCALATION, INVESTIGATION, SAFE_PLAN)
    report = run_case(
        [raw_event],
        client=client,
        investigator_toolbox=FakeToolbox(),
        responder_toolbox=FakeToolbox(),
    )
    assert report.final_state == "closed_resolved_suggested"


def test_a_dropped_case_is_still_a_recorded_decision(raw_event) -> None:
    report = run_case([raw_event], client=_client(DROP), incident_id="fp-backup-01")
    assert report.final_state == "closed_false_positive"
    assert report.incident_id == "fp-backup-01"
    assert report.investigation is None and report.response_plan is None
    assert "backup" in report.incident.rationale.lower()
    assert [e.stage for e in report.audit_log] == ["detection", "orchestration"]


def test_the_audit_log_names_the_model_behind_each_stage(raw_event) -> None:
    client = _client(ESCALATION, INVESTIGATION, PLAN)
    report = run_case(
        [raw_event],
        client=client,
        detector_model="detector-model",
        investigator_model="investigator-model",
        responder_model="responder-model",
        investigator_toolbox=FakeToolbox(),
        responder_toolbox=FakeToolbox(),
    )
    models = {e.stage: e.model for e in report.audit_log}
    assert models["detection"] == "detector-model"
    assert models["investigation"] == "investigator-model"
    assert models["response"] == "responder-model"
    assert models["orchestration"] is None  # no model decides a state transition


def test_an_agent_failure_surfaces_as_an_orchestrator_error(raw_event) -> None:
    client = FakeClient(["not json at all"] * 3)
    with pytest.raises(OrchestratorError, match="detection failed"):
        run_case([raw_event], client=client)


def test_run_case_refuses_an_empty_batch() -> None:
    with pytest.raises(OrchestratorError):
        run_case([], client=FakeClient([]))


# --------------------------------------------------------------------------
# scenario loading and reporting
# --------------------------------------------------------------------------
def test_load_events_parses_a_bundled_scenario() -> None:
    events = load_events("data/scenarios/phishing-01.json")
    assert events and events[0].event_id


def test_load_events_rejects_a_file_that_is_not_a_list(tmp_path) -> None:
    path = tmp_path / "bad.json"
    path.write_text('{"event_id": "evt-1"}', encoding="utf-8")
    with pytest.raises(OrchestratorError):
        load_events(path)


def test_the_report_shows_the_plan_and_the_audit_trail(raw_event, tmp_path) -> None:
    client = _client(ESCALATION, INVESTIGATION, PLAN)
    report = run_case(
        [raw_event],
        client=client,
        investigator_toolbox=FakeToolbox(),
        responder_toolbox=FakeToolbox(),
    )
    markdown = render_markdown(report)
    assert "## Response plan" in markdown
    assert "human approval required" in markdown
    assert "T1110.001" in markdown
    assert "## Audit log" in markdown

    md_path, json_path = write_report(report, tmp_path)
    assert md_path.exists() and json_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8"))["incident_id"] == "inc-0001"
