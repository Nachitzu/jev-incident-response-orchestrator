"""End-to-end state machine over scripted offline replies."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from conftest import FakeJev, FakeStructuredLLM, FakeTriage

from orchestrator._llm import LLMError
from orchestrator.orchestrator import OrchestratorError, load_events, run_case
from orchestrator.schemas import (
    Incident,
    IncidentCategory,
    Investigation,
    PlaybookStep,
    RawEvent,
    ResponsePlan,
    Severity,
)

NOW = datetime(2026, 7, 8, 4, 0, tzinfo=UTC)


def _scenario_file(tmp_path, events: list):
    path = tmp_path / "scenario.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    return path


def _benign_incident(event_id: str = "evt-0001") -> Incident:
    return Incident(
        incident_id=f"INC-{event_id}",
        source_event_id=event_id,
        title="Noise",
        summary="Scheduled backup traffic.",
        severity=Severity.LOW,
        category=IncidentCategory.OTHER,
        confidence=0.90,
        escalate=False,
        false_positive_reason="matches the backup window",
    )


# --------------------------------------------------------------------------
# load_events
# --------------------------------------------------------------------------
def test_load_events_reads_a_real_scenario():
    from orchestrator.tools import intel

    path = intel.data_dir() / "scenarios" / "phishing-01.json"
    events = load_events(path)
    assert events and all(isinstance(e, RawEvent) for e in events)


def test_load_events_rejects_empty_array(tmp_path):
    path = _scenario_file(tmp_path, [])
    with pytest.raises(OrchestratorError, match="non-empty"):
        load_events(path)


def test_load_events_reports_invalid_events(tmp_path):
    path = _scenario_file(tmp_path, [{"event_id": ""}])
    with pytest.raises(OrchestratorError, match="RawEvent"):
        load_events(path)


# --------------------------------------------------------------------------
# run_case
# --------------------------------------------------------------------------
def test_run_case_requires_events():
    with pytest.raises(OrchestratorError):
        run_case([], llm_client=FakeStructuredLLM([]))


def test_run_case_escalates_and_audits(incident, investigation, response_plan, raw_event):
    llm = FakeStructuredLLM([incident, investigation, response_plan])
    report = run_case([raw_event], llm_client=llm, now=lambda: NOW)
    assert report.final_state == "escalated_to_human"
    assert report.incident_id == "inc-0001"
    assert report.investigation is not None and report.response_plan is not None
    actions = [(e.stage, e.action) for e in report.audit_log]
    assert ("orchestration", "escalate") in actions
    assert ("orchestration", "escalated_to_human") in actions
    assert report.generated_at == NOW


def test_run_case_closes_false_positive(raw_event):
    """A dropped scenario still yields a full, auditable report."""
    llm = FakeStructuredLLM([_benign_incident()])
    report = run_case([raw_event], llm_client=llm, incident_id="CASE-QUIET")
    assert report.final_state == "closed_false_positive"
    assert report.incident_id == "CASE-QUIET"
    assert report.investigation is None and report.response_plan is None
    assert any(a == "closed_false_positive" for _, a in [(e.stage, e.action) for e in report.audit_log])
    assert len(llm.calls) == 1  # never advanced past detection


def test_run_case_auto_closes_a_fully_safe_plan(
    investigation, safe_step, raw_event
):
    mid = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Suspicious recon sweep",
        summary="Internal scan by a known scanner.",
        severity=Severity.MEDIUM,
        category=IncidentCategory.RECON,
        confidence=0.88,
        escalate=True,
    )
    plan = ResponsePlan(
        incident_id="inc-0001",
        planned_at=NOW,
        playbook_name="recon",
        summary="Log and watch; nothing to approve.",
        steps=[safe_step],
        requires_human_approval=False,
        residual_risk="Negligible.",
    )
    llm = FakeStructuredLLM([mid, investigation, plan])
    report = run_case([raw_event], llm_client=llm)
    assert report.final_state == "closed_resolved_suggested"


def test_run_case_low_confidence_score_forces_human_review(
    investigation, safe_step, raw_event
):
    """Even an auto-safe plan lands on a desk when Jev's score is bimodal."""
    mid = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Ambiguous activity",
        summary="Two plausible interpretations.",
        severity=Severity.MEDIUM,
        category=IncidentCategory.RECON,
        confidence=0.75,
        escalate=True,
    )
    plan = ResponsePlan(
        incident_id="inc-0001",
        planned_at=NOW,
        playbook_name="recon",
        summary="Watch and log.",
        steps=[safe_step],
        requires_human_approval=False,
        residual_risk="Ambiguous intent.",
    )
    jev = FakeJev(
        triage=FakeTriage(
            is_threat_prob=0.8, requires_escalation=True, severity_confidence=0.30
        )
    )
    llm = FakeStructuredLLM([mid, investigation, plan])
    report = run_case([raw_event], llm_client=llm, jev_engine=jev)
    assert report.final_state == "escalated_to_human"
    assert any(e.stage == "detect:low_confidence_score" for e in report.audit_log)


def test_run_case_carries_the_strongest_escalation(investigation, response_plan):
    event2 = RawEvent(
        event_id="evt-0002",
        source="EDR",
        event_type="credential_use",
        raw_payload={"logon": "smb", "from": "10.0.1.12"},
    )
    first = Incident(
        incident_id="inc-low",
        source_event_id="evt-0001",
        title="Minor anomaly",
        summary="Possibly relevant.",
        severity=Severity.LOW,
        category=IncidentCategory.RECON,
        confidence=0.60,
        escalate=True,
    )
    second = Incident(
        incident_id="inc-high",
        source_event_id="evt-0002",
        title="Stolen credential replayed",
        summary="Lateral movement in progress.",
        severity=Severity.CRITICAL,
        category=IncidentCategory.LATERAL_MOVEMENT,
        confidence=0.95,
        escalate=True,
    )
    for payload in (investigation, response_plan):
        payload.incident_id = "inc-high"
    event1 = RawEvent(
        event_id="evt-0001",
        source="EDR",
        event_type="scan",
        raw_payload={"ports": 1024},
    )
    llm = FakeStructuredLLM([first, second, investigation, response_plan])
    report = run_case([event1, event2], llm_client=llm)
    assert report.incident_id == "inc-high"
    assert report.final_state == "escalated_to_human"


def test_run_case_wraps_llm_failures(raw_event):
    llm = FakeStructuredLLM([LLMError("boom")])
    with pytest.raises(OrchestratorError, match="detection failed"):
        run_case([raw_event], llm_client=llm)


def test_run_case_detects_incident_id_drift(incident, raw_event):
    wrong = Investigation(
        incident_id="inc-other",
        hypothesis="Wrong case.",
        recommended_severity=Severity.HIGH,
    )
    llm = FakeStructuredLLM([incident, wrong])
    with pytest.raises(OrchestratorError, match="drifted"):
        run_case([raw_event], llm_client=llm)


def test_run_case_honours_hitl_threshold_env(
    investigation, safe_step, raw_event, monkeypatch
):
    """SOAR_HITL_CONFIDENCE_MIN must reach the detector's confidence floor."""
    monkeypatch.setenv("SOAR_HITL_CONFIDENCE_MIN", "0.95")
    mid = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Watch item",
        summary="Might matter.",
        severity=Severity.MEDIUM,
        category=IncidentCategory.RECON,
        confidence=0.85,
        escalate=True,
    )
    plan = ResponsePlan(
        incident_id="inc-0001",
        planned_at=NOW,
        playbook_name="recon",
        summary="Log it.",
        steps=[safe_step],
        requires_human_approval=False,
        residual_risk="Low.",
    )
    jev = FakeJev(
        triage=FakeTriage(
            is_threat_prob=0.8, requires_escalation=True, severity_confidence=0.90
        )
    )
    llm = FakeStructuredLLM([mid, investigation, plan])
    report = run_case([raw_event], llm_client=llm, jev_engine=jev)
    assert report.final_state == "escalated_to_human"


# --------------------------------------------------------------------------
# Model tier routing
# --------------------------------------------------------------------------
def _cascade_payloads() -> list:
    """Detector incident, ungrounded draft, corrected draft, safe plan."""
    high = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Sustained brute force",
        summary="Repeated successful auth anomalies.",
        severity=Severity.HIGH,
        category=IncidentCategory.BRUTE_FORCE,
        confidence=0.82,
        escalate=True,
    )
    draft1 = Investigation(
        incident_id="inc-0001", hypothesis="Draft guess.", recommended_severity=Severity.HIGH
    )
    draft2 = Investigation(
        incident_id="inc-0001",
        hypothesis="Corrected, grounded hypothesis.",
        recommended_severity=Severity.HIGH,
    )
    plan = ResponsePlan(
        incident_id="inc-0001",
        planned_at=NOW,
        playbook_name="brute_force",
        summary="Watch and rotate.",
        steps=[
            PlaybookStep(
                order=1,
                phase="containment",
                action="Notify the on-call analyst",
                requires_approval=False,
                justification="Non-destructive.",
            )
        ],
        requires_human_approval=False,
        residual_risk="Low.",
    )
    return [high, draft1, draft2, plan]


_UNGROUNDED = {"grounded_in_iocs": 0.40, "mitre_coherent": 0.90}


def test_run_case_routes_model_tiers(raw_event):
    """Fast tier for detector + first SDE step; reasoning tier for escalation + responder."""
    jev = FakeJev(
        triage=FakeTriage(is_threat_prob=0.8, requires_escalation=True),
        grounding_checks=_UNGROUNDED,
    )
    llm = FakeStructuredLLM(_cascade_payloads())
    run_case(
        [raw_event],
        llm_client=llm,
        jev_engine=jev,
        fast_model="tier-fast",
        reasoning_model="tier-deep",
    )
    assert [c["model"] for c in llm.calls] == [
        "tier-fast",
        "tier-fast",
        "tier-deep",
        "tier-deep",
    ]


def test_run_case_default_tiers_follow_the_provider(raw_event, monkeypatch):
    """Without explicit overrides the provider's own (fast, reasoning) pair routes."""
    monkeypatch.setenv("SOAR_LLM_PROVIDER", "deepseek")
    jev = FakeJev(
        triage=FakeTriage(is_threat_prob=0.8, requires_escalation=True),
        grounding_checks=_UNGROUNDED,
    )
    llm = FakeStructuredLLM(_cascade_payloads())
    run_case([raw_event], llm_client=llm, jev_engine=jev)
    assert [c["model"] for c in llm.calls] == [
        "deepseek-flash",
        "deepseek-flash",
        "deepseek-v4-pro",
        "deepseek-v4-pro",
    ]


def test_cli_explains_a_missing_provider_key(monkeypatch):
    from orchestrator.cli import _build_client

    monkeypatch.setenv("SOAR_LLM_PROVIDER", "deepseek")
    with pytest.raises(SystemExit, match="DEEPSEEK_API_KEY"):
        _build_client()


def test_cli_rejects_an_unknown_provider_cleanly(monkeypatch):
    from orchestrator.cli import _build_client

    monkeypatch.setenv("SOAR_LLM_PROVIDER", "grok")
    with pytest.raises(SystemExit, match="SOAR_LLM_PROVIDER"):
        _build_client()
