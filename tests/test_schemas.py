"""Contract tests: the Pydantic schemas are the safety boundary of the system.

Each business rule lives in a `@model_validator`/`@field_validator`; every one is
exercised in both its accepting and its rejecting direction. If these pass, no
malformed contract can reach an agent.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from src.orchestrator.schemas import (
    AuditEntry,
    CaseReport,
    DetectionResult,
    Incident,
    Investigation,
    MitreTechnique,
    Observable,
    PlaybookStep,
    RawEvent,
    ResponsePlan,
)

UTC = timezone.utc


# --------------------------------------------------------------------------
# Observable
# --------------------------------------------------------------------------


def test_observable_ip_valid() -> None:
    obs = Observable(type="ip", value="10.0.0.5")
    assert obs.value == "10.0.0.5"


def test_observable_ip_invalid_rejected() -> None:
    with pytest.raises(ValidationError, match="valid IP"):
        Observable(type="ip", value="not-an-ip")


def test_observable_sha256_length_enforced() -> None:
    with pytest.raises(ValidationError, match="SHA-256"):
        Observable(type="sha256", value="abc123")
    Observable(type="sha256", value="a" * 64)  # valid


def test_observable_md5_and_email() -> None:
    with pytest.raises(ValidationError, match="MD5"):
        Observable(type="md5", value="xyz")
    with pytest.raises(ValidationError, match="email"):
        Observable(type="email", value="no-at-sign")
    Observable(type="email", value="user@example.com")


# --------------------------------------------------------------------------
# RawEvent
# --------------------------------------------------------------------------


def test_raw_event_naive_timestamp_becomes_utc() -> None:
    event = RawEvent(
        event_id="evt-1",
        source="IDS",
        event_type="dns_query",
        raw_log="beacon",
        timestamp="2026-07-08T03:00:00",  # naive
    )
    assert event.timestamp is not None
    assert event.timestamp.tzinfo is not None


def test_raw_event_rejects_bad_ip() -> None:
    with pytest.raises(ValidationError, match="valid IP"):
        RawEvent(
            event_id="evt-1",
            source="fw",
            event_type="conn",
            raw_log="x",
            source_ip="999.999.1.1",
        )


def test_raw_event_missing_fields_and_internal(raw_event: RawEvent) -> None:
    assert raw_event.source_is_internal is False  # public source ip
    minimal = RawEvent(event_id="e", source="s", event_type="t", raw_log="l")
    assert set(minimal.missing_fields) == {
        "timestamp",
        "source_ip",
        "dest_ip",
        "user",
        "host",
    }


# --------------------------------------------------------------------------
# Incident + DetectionResult
# --------------------------------------------------------------------------


def test_incident_valid(incident: Incident) -> None:
    assert incident.status == "detected"


def test_incident_high_severity_requires_confidence() -> None:
    with pytest.raises(ValidationError, match="detection_confidence >= 0.5"):
        Incident(
            incident_id="inc-x",
            created_at=datetime(2026, 7, 8, tzinfo=UTC),
            triggering_events=["e1"],
            title="t",
            category="malware",
            severity="CRITICAL",
            detection_confidence=0.2,
            rationale="thin",
        )


def test_incident_requires_triggering_events() -> None:
    with pytest.raises(ValidationError):
        Incident(
            incident_id="inc-x",
            created_at=datetime(2026, 7, 8, tzinfo=UTC),
            triggering_events=[],
            title="t",
            category="other",
            severity="LOW",
            detection_confidence=0.1,
            rationale="r",
        )


def test_detection_result_escalate_requires_incident(incident: Incident) -> None:
    with pytest.raises(ValidationError, match="requires an incident"):
        DetectionResult(escalate=True)
    ok = DetectionResult(escalate=True, incident=incident)
    assert ok.incident is incident


def test_detection_result_drop_requires_reason() -> None:
    with pytest.raises(ValidationError, match="drop_reason"):
        DetectionResult(escalate=False)
    dropped = DetectionResult(escalate=False, drop_reason="nightly scanner 10.0.9.15")
    assert dropped.incident is None


def test_detection_result_drop_cannot_carry_incident(incident: Incident) -> None:
    with pytest.raises(ValidationError, match="must not carry an incident"):
        DetectionResult(escalate=False, drop_reason="noise", incident=incident)


# --------------------------------------------------------------------------
# Investigation + MitreTechnique
# --------------------------------------------------------------------------


def test_mitre_technique_format() -> None:
    MitreTechnique(technique_id="T1566", name="Phishing", tactic="Initial Access")
    MitreTechnique(technique_id="T1566.001", name="Spearphishing", tactic="IA")
    with pytest.raises(ValidationError, match="T1566"):
        MitreTechnique(technique_id="1566", name="x", tactic="y")


def test_investigation_requires_evidence(mitre_technique: MitreTechnique) -> None:
    with pytest.raises(ValidationError):
        Investigation(
            incident_id="inc-1",
            investigated_at=datetime(2026, 7, 8, tzinfo=UTC),
            mitre_techniques=[mitre_technique],
            hypothesis="h",
            confidence=0.5,
            kill_chain_stage="exploitation",
            evidence=[],  # empty
            recommended_severity="HIGH",
        )


def test_investigation_rejects_blank_evidence(mitre_technique: MitreTechnique) -> None:
    with pytest.raises(ValidationError, match="blank"):
        Investigation(
            incident_id="inc-1",
            investigated_at=datetime(2026, 7, 8, tzinfo=UTC),
            mitre_techniques=[mitre_technique],
            hypothesis="h",
            confidence=0.5,
            kill_chain_stage="exploitation",
            evidence=["   "],
            recommended_severity="HIGH",
        )


def test_investigation_valid(investigation: Investigation) -> None:
    assert investigation.recommended_severity == "CRITICAL"


# --------------------------------------------------------------------------
# PlaybookStep + ResponsePlan (human-in-the-loop invariants)
# --------------------------------------------------------------------------


def test_destructive_step_must_require_approval() -> None:
    with pytest.raises(ValidationError, match="requires_approval=True"):
        PlaybookStep(
            order=1,
            phase="containment",
            action="Isolate host dc01",
            requires_approval=False,
            justification="j",
        )


def test_automatable_step_cannot_require_approval() -> None:
    with pytest.raises(ValidationError, match="cannot be both automatable"):
        PlaybookStep(
            order=1,
            phase="recovery",
            action="Restore from backup",
            requires_approval=True,
            automatable=True,
            justification="j",
        )


def test_step_is_destructive_property(destructive_step: PlaybookStep) -> None:
    assert destructive_step.is_destructive is True


def test_response_plan_approval_flag_matches_steps(response_plan: ResponsePlan) -> None:
    assert response_plan.requires_human_approval is True


def test_response_plan_flag_mismatch_rejected(safe_step: PlaybookStep) -> None:
    with pytest.raises(ValidationError, match="requires_human_approval must equal"):
        ResponsePlan(
            incident_id="inc-1",
            planned_at=datetime(2026, 7, 8, tzinfo=UTC),
            playbook_name="p",
            summary="s",
            steps=[safe_step],
            requires_human_approval=True,  # no step requires approval
            residual_risk="r",
        )


def test_response_plan_unique_orders(safe_step: PlaybookStep) -> None:
    dup = safe_step.model_copy()
    with pytest.raises(ValidationError, match="unique"):
        ResponsePlan(
            incident_id="inc-1",
            planned_at=datetime(2026, 7, 8, tzinfo=UTC),
            playbook_name="p",
            summary="s",
            steps=[safe_step, dup],
            requires_human_approval=False,
            residual_risk="r",
        )


# --------------------------------------------------------------------------
# CaseReport (state consistency)
# --------------------------------------------------------------------------


def test_case_report_false_positive_has_no_investigation(incident: Incident) -> None:
    report = CaseReport(
        incident_id="inc-0001",
        incident=incident,
        final_state="closed_false_positive",
        generated_at=datetime(2026, 7, 8, tzinfo=UTC),
    )
    assert report.investigation is None


def test_case_report_false_positive_rejects_investigation(
    incident: Incident, investigation: Investigation
) -> None:
    with pytest.raises(ValidationError, match="closed_false_positive cannot carry"):
        CaseReport(
            incident_id="inc-0001",
            incident=incident,
            investigation=investigation,
            final_state="closed_false_positive",
            generated_at=datetime(2026, 7, 8, tzinfo=UTC),
        )


def test_case_report_escalated_requires_investigation(incident: Incident) -> None:
    with pytest.raises(ValidationError, match="requires an investigation"):
        CaseReport(
            incident_id="inc-0001",
            incident=incident,
            final_state="escalated_to_human",
            generated_at=datetime(2026, 7, 8, tzinfo=UTC),
        )


def test_case_report_incident_id_must_thread(
    incident: Incident, investigation: Investigation
) -> None:
    with pytest.raises(ValidationError, match="must match"):
        CaseReport(
            incident_id="different-id",
            incident=incident,
            investigation=investigation,
            final_state="escalated_to_human",
            generated_at=datetime(2026, 7, 8, tzinfo=UTC),
        )


def test_case_report_full_valid(
    incident: Incident,
    investigation: Investigation,
    response_plan: ResponsePlan,
    audit_entry: AuditEntry,
) -> None:
    report = CaseReport(
        incident_id="inc-0001",
        incident=incident,
        investigation=investigation,
        response_plan=response_plan,
        final_state="escalated_to_human",
        audit_log=[audit_entry],
        generated_at=datetime(2026, 7, 8, 3, 30, tzinfo=UTC),
    )
    assert report.final_state == "escalated_to_human"
    assert len(report.audit_log) == 1
