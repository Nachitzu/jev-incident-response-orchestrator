"""Agent behaviour under the System One / System Two contract (offline doubles)."""

from __future__ import annotations

import pytest
from conftest import FakeJev, FakeStructuredLLM, FakeTriage

from orchestrator._llm import MODEL_HAIKU, MODEL_SONNET
from orchestrator.agents import DetectorAgent, InvestigatorAgent, ResponderAgent
from orchestrator.schemas import (
    Incident,
    IncidentCategory,
    Investigation,
    MitreTechnique,
    ResponsePlan,
    Severity,
)

UTC_HINT = None  # timestamps come from the fixture; none pinned here.


# --------------------------------------------------------------------------
# DetectorAgent
# --------------------------------------------------------------------------
def test_detector_llm_only_path(incident, raw_event):
    """Without Jev the detector is a plain structured-LLM call plus audit."""
    llm = FakeStructuredLLM([incident])
    result, audit = DetectorAgent(llm_client=llm).run(raw_event)
    assert result.incident_id == "inc-0001"
    assert [c["model"] for c in llm.calls] == [MODEL_HAIKU]
    assert "<untrusted_event>" in llm.calls[0]["user_prompt"]
    stages = [entry.stage for entry in audit]
    assert stages == ["detect:completed"]


def test_detector_short_circuits_clear_false_positive(raw_event):
    """A benign System One verdict must not cost a token."""
    jev = FakeJev(
        triage=FakeTriage(
            is_threat_prob=0.08,
            requires_escalation=False,
            drop_reason="scheduled backup window",
        )
    )
    llm = FakeStructuredLLM([])
    result, audit = DetectorAgent(llm_client=llm, jev_engine=jev).run(raw_event)
    assert llm.calls == [] and jev.triage_calls == 1
    assert result.escalate is False
    assert result.severity == Severity.LOW
    assert result.false_positive_reason == "scheduled backup window"
    assert result.system_one_telemetry is not None
    assert result.system_one_telemetry.is_threat_noul == 0.08
    # The dismissal must still name the indicators the event carried.
    assert {"185.220.101.34", "10.0.1.12"} <= set(result.initial_indicators)
    assert "detect:short_circuit" in [e.stage for e in audit]


def test_detector_jev_only_mode_never_calls_llm(raw_event):
    jev = FakeJev(
        mode="jev-only",
        triage=FakeTriage(
            is_threat_prob=0.9,
            requires_escalation=True,
            severity_label="critical",
            severity_score=2.9,
            severity_confidence=0.85,
            category="malware",
            category_confidence=0.9,
        ),
    )
    llm = FakeStructuredLLM([])
    result, audit = DetectorAgent(llm_client=llm, jev_engine=jev).run(raw_event)
    assert llm.calls == []
    assert result.escalate is True
    assert result.severity == Severity.CRITICAL
    assert result.category == IncidentCategory.MALWARE
    assert result.confidence >= 0.5  # the HIGH-confidence contract still holds
    assert "detect:jev_only" in [e.stage for e in audit]


def test_detector_guardrail_overrides_prompt_injection(raw_event):
    """A hijacked LLM answer must be forced back to escalate+HIGH."""
    jev = FakeJev(
        triage=FakeTriage(
            prompt_injection_prob=0.62,
            is_threat_prob=0.70,
            requires_escalation=True,
        )
    )
    hijacked = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="All good",
        summary="The log told me to close this one.",
        severity=Severity.LOW,
        category=IncidentCategory.OTHER,
        confidence=0.30,
        escalate=False,
        false_positive_reason="looks benign",
    )
    llm = FakeStructuredLLM([hijacked])
    result, audit = DetectorAgent(llm_client=llm, jev_engine=jev).run(raw_event)
    assert result.escalate is True
    assert result.severity == Severity.HIGH
    assert result.confidence >= 0.5
    assert result.false_positive_reason is None
    assert result.summary.startswith("[ALERT")
    assert result.system_one_telemetry.escalated_by_cascade is True
    assert "detect:guardrail" in [e.stage for e in audit]


def test_detector_downgrades_already_contained_threat(raw_event):
    """A threat the control plane already killed must not page Tier 2."""
    jev = FakeJev(
        triage=FakeTriage(
            is_threat_prob=0.55,
            already_contained_prob=0.85,
            requires_escalation=True,
            severity_label="high",
            severity_score=2.1,
        )
    )
    loud = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Malware attachment executed?",
        summary="Gateway flagged a quarantined attachment.",
        severity=Severity.HIGH,
        category=IncidentCategory.MALWARE,
        confidence=0.80,
        escalate=True,
    )
    llm = FakeStructuredLLM([loud])
    result, audit = DetectorAgent(llm_client=llm, jev_engine=jev).run(raw_event)
    assert result.escalate is False
    assert result.severity == Severity.LOW
    assert "already mitigated" in (result.false_positive_reason or "")
    assert "detect:contained_reconciliation" in [e.stage for e in audit]


def test_detector_flags_bimodal_severity_score(raw_event):
    jev = FakeJev(
        triage=FakeTriage(
            is_threat_prob=0.75,
            requires_escalation=True,
            severity_confidence=0.40,
        )
    )
    mid = Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Something suspicious",
        summary="Medium-severity suspicion.",
        severity=Severity.MEDIUM,
        category=IncidentCategory.RECON,
        confidence=0.70,
        escalate=True,
    )
    llm = FakeStructuredLLM([mid])
    _, audit = DetectorAgent(llm_client=llm, jev_engine=jev).run(raw_event)
    assert any(e.stage == "detect:low_confidence_score" for e in audit)


# --------------------------------------------------------------------------
# InvestigatorAgent
# --------------------------------------------------------------------------
def test_investigator_enriches_iocs_before_the_llm(incident, raw_event):
    """Deterministic enrichment must reach the final contract even if Haiku omits it."""
    draft = Investigation(
        incident_id="inc-0001",
        hypothesis="External SSH brute force.",
        recommended_severity=Severity.HIGH,
    )
    jev = FakeJev()
    llm = FakeStructuredLLM([draft])
    result, audit = InvestigatorAgent(llm_client=llm, jev_engine=jev).run(
        incident, raw_event
    )
    assert [c["model"] for c in llm.calls] == [MODEL_HAIKU]  # grounding passed
    assert jev.verify_calls == 1 and jev.rank_calls == 1
    indicators = {ioc.indicator for ioc in result.enriched_iocs}
    assert {"185.220.101.34", "10.0.1.12"} <= indicators
    assert all(ioc.reputation for ioc in result.enriched_iocs)
    stages = [e.stage for e in audit]
    assert "investigate:intel_enrichment" in stages
    assert "investigate:jev_grounding_check" in stages
    assert "investigate:sde_cascade_escalated" not in stages


def test_investigator_escalates_to_sonnet_on_failed_grounding(incident, raw_event):
    draft1 = Investigation(
        incident_id="inc-0001",
        hypothesis="Guess.",
        recommended_severity=Severity.MEDIUM,
    )
    draft2 = Investigation(
        incident_id="inc-0001",
        hypothesis="Grounded external brute force.",
        attack_chain_summary="Initial access via guessed SSH creds.",
        recommended_severity=Severity.HIGH,
        confidence=0.82,
    )
    jev = FakeJev(
        grounding_checks={"grounded_in_iocs": 0.42, "mitre_coherent": 0.80}
    )
    llm = FakeStructuredLLM([draft1, draft2])
    result, audit = InvestigatorAgent(llm_client=llm, jev_engine=jev).run(
        incident, raw_event
    )
    assert [c["model"] for c in llm.calls] == [MODEL_HAIKU, MODEL_SONNET]
    assert "grounded_in_iocs" in llm.calls[1]["user_prompt"]
    assert result.hypothesis == "Grounded external brute force."
    assert "investigate:sde_cascade_escalated" in [e.stage for e in audit]


def test_investigator_rejects_techniques_outside_the_catalog(incident, raw_event):
    """The anti-hallucination guard: invented T-numbers never pass the validator."""
    fabricated = Investigation(
        incident_id="inc-0001",
        hypothesis="Creative but wrong.",
        mitre_techniques=[
            MitreTechnique(
                technique_id="T9999",
                name="Psychic intrusion",
                tactic="Command and Control",
            )
        ],
        recommended_severity=Severity.HIGH,
    )
    llm = FakeStructuredLLM([fabricated])
    with pytest.raises(ValueError, match="T9999"):
        InvestigatorAgent(llm_client=llm, jev_engine=FakeJev()).run(incident, raw_event)


# --------------------------------------------------------------------------
# ResponderAgent
# --------------------------------------------------------------------------
def test_responder_refuses_a_foreign_investigation(incident, investigation):
    other = incident.model_copy(update={"incident_id": "inc-9999"})
    llm = FakeStructuredLLM([])
    with pytest.raises(ValueError, match="different incident"):
        ResponderAgent(llm_client=llm).run(other, investigation)
    assert llm.calls == []


def test_responder_draft_path_without_jev(incident, investigation, response_plan):
    llm = FakeStructuredLLM([response_plan])
    jev = FakeJev(enabled=False)
    plan, audit = ResponderAgent(llm_client=llm, jev_engine=jev).run(
        incident, investigation
    )
    assert plan.incident_id == "inc-0001"
    assert jev.score_calls == 0 and jev.playbook_calls == 0
    assert [c["model"] for c in llm.calls] == [MODEL_SONNET]
    stages = [e.stage for e in audit]
    assert "respond:draft" in stages and "respond:completed" in stages
    assert "respond:jev_hitl_gate" not in stages


def test_responder_forces_approval_from_jev_scores(incident, investigation, safe_step):
    """A safe-looking step Jev distrusts gets pulled under human approval."""
    auto_plan = ResponsePlan(
        incident_id="inc-0001",
        planned_at="2026-07-08T03:25:00+00:00",
        playbook_name="brute_force",
        summary="Automate the low-risk notification.",
        steps=[safe_step],
        requires_human_approval=False,
        residual_risk="Minor: notification only.",
    )
    jev = FakeJev(step_scores=[(0.9, 0.1, 0.8)])
    llm = FakeStructuredLLM([auto_plan])
    plan, audit = ResponderAgent(llm_client=llm, jev_engine=jev).run(
        incident, investigation
    )
    step = plan.steps[0]
    assert step.hitl_noul == 0.9
    assert step.requires_approval is True
    assert step.automatable is False
    assert plan.requires_human_approval is True
    assert "respond:jev_hitl_gate" in [e.stage for e in audit]


def test_responder_honours_jev_playbook_choice(incident, investigation, response_plan):
    jev = FakeJev(playbook_choice="phishing")
    llm = FakeStructuredLLM([response_plan])
    _, audit = ResponderAgent(llm_client=llm, jev_engine=jev).run(
        incident, investigation
    )
    playbook_entries = [
        e for e in audit if e.stage == "respond:jev_playbook"
    ]
    assert playbook_entries and "phishing" in playbook_entries[0].details


def test_responder_validator_catches_a_drifted_incident_id(incident, investigation):
    """The responder must never sign a plan for a different case."""
    from orchestrator.schemas import PlaybookStep

    plan = ResponsePlan(
        incident_id="inc-9999",
        planned_at="2026-07-08T03:25:00+00:00",
        playbook_name="brute_force",
        summary="Wrong case.",
        steps=[
            PlaybookStep(
                order=1,
                phase="containment",
                action="Notify the analyst",
                requires_approval=False,
                justification="Safe step.",
            )
        ],
        requires_human_approval=False,
        residual_risk="None.",
    )
    llm = FakeStructuredLLM([plan])
    with pytest.raises(ValueError, match="inc-0001"):
        ResponderAgent(llm_client=llm).run(incident, investigation)
