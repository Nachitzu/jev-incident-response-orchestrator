"""Contract-level tests: enums, guard validators, and shared helpers."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from orchestrator.schemas import (
    AuditEntry,
    CaseReport,
    EnrichedIOC,
    Incident,
    IncidentCategory,
    Investigation,
    MitreTechnique,
    Observable,
    PlaybookStep,
    RawEvent,
    ResponsePlan,
    Severity,
    SystemOneTelemetry,
)
from orchestrator.schemas.common import (
    ensure_aware,
    guess_indicator_type,
    is_internal_ip,
)

NOW = datetime(2026, 7, 8, 3, 0, tzinfo=UTC)


# --------------------------------------------------------------------------
# enums
# --------------------------------------------------------------------------
def test_severity_behaves_as_string_and_enum():
    assert Severity.HIGH == "HIGH"
    assert Severity("LOW") is Severity.LOW
    assert {s.value for s in Severity} == {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    with pytest.raises(ValueError):
        Severity("SEVERE")


def test_category_enum_and_unknown_values():
    assert IncidentCategory("brute_force") is IncidentCategory.BRUTE_FORCE
    with pytest.raises(ValueError):
        IncidentCategory("cryptojacking")


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def test_is_internal_ip():
    assert is_internal_ip("10.0.1.12")
    assert not is_internal_ip("8.8.8.8")
    assert not is_internal_ip("not-an-ip")
    assert not is_internal_ip(None)


def test_guess_indicator_type():
    assert guess_indicator_type("8.8.8.8") == "ip"
    assert guess_indicator_type("a" * 64) == "sha256"
    assert guess_indicator_type("a" * 32) == "md5"
    assert guess_indicator_type("https://evil.example/x") == "url"
    assert guess_indicator_type("phish@evil.example") == "email"
    assert guess_indicator_type("C:\\Windows\\temp\\x.exe") == "filepath"
    assert guess_indicator_type("evil.example") == "domain"


def test_ensure_aware_treats_naive_as_utc():
    naive = datetime(2026, 1, 1, 12, 0)
    aware = ensure_aware(naive)
    assert aware is not None and aware.tzinfo is not None
    assert ensure_aware(None) is None


# --------------------------------------------------------------------------
# Observable
# --------------------------------------------------------------------------
def test_observable_type_must_match_value():
    Observable(type="ip", value="185.220.101.34")
    with pytest.raises(ValidationError, match="valid IP"):
        Observable(type="ip", value="not-an-ip")
    with pytest.raises(ValidationError, match="SHA-256"):
        Observable(type="sha256", value="deadbeef")
    with pytest.raises(ValidationError, match="email"):
        Observable(type="email", value="nope")


# --------------------------------------------------------------------------
# AuditEntry
# --------------------------------------------------------------------------
def test_audit_entry_fields_and_naive_timestamp():
    entry = AuditEntry(
        timestamp=datetime(2026, 7, 8, 3, 0),
        stage="detect:jev_system_one",
        actor="JevEngine (System One)",
        action="speculative_fanout_triage",
        details="is_threat=0.90",
    )
    assert entry.timestamp.tzinfo is not None
    with pytest.raises(ValidationError):
        AuditEntry(timestamp=NOW, stage="", actor="x", action="y")


def test_telemetry_bounds():
    SystemOneTelemetry(is_threat_noul=0.5, severity_score=1.5)
    with pytest.raises(ValidationError):
        SystemOneTelemetry(is_threat_noul=1.2)
    with pytest.raises(ValidationError):
        SystemOneTelemetry(severity_score=3.5)


# --------------------------------------------------------------------------
# Incident
# --------------------------------------------------------------------------
def test_high_escalation_needs_even_odds():
    with pytest.raises(ValidationError, match="confidence"):
        Incident(
            incident_id="i",
            title="t",
            summary="s",
            severity=Severity.CRITICAL,
            category=IncidentCategory.OTHER,
            confidence=0.2,
            escalate=True,
        )


def test_dismissal_must_state_a_reason():
    with pytest.raises(ValidationError, match="false_positive_reason"):
        Incident(
            incident_id="i",
            title="t",
            summary="s",
            severity=Severity.LOW,
            category=IncidentCategory.OTHER,
            confidence=0.9,
            escalate=False,
        )


# --------------------------------------------------------------------------
# RawEvent
# --------------------------------------------------------------------------
def test_raw_event_accepts_historic_siem_spellings():
    event = RawEvent(
        event_id="e1",
        source="firewall",
        event_type="deny",
        host="fw-01",
        dest_ip="8.8.8.8",
        raw_log="deny udp",
    )
    assert event.hostname == "fw-01"
    assert event.destination_ip == "8.8.8.8"


def test_raw_event_must_carry_content():
    with pytest.raises(ValidationError, match="raw_log or raw_payload"):
        RawEvent(event_id="e1", source="syslog", event_type="x")
    RawEvent(event_id="e1", source="syslog", event_type="x", raw_payload={"k": 1})


def test_raw_event_rejects_bad_ips():
    with pytest.raises(ValidationError, match="IP address"):
        RawEvent(
            event_id="e1",
            source="s",
            event_type="x",
            source_ip="999.1.1.1",
            raw_payload={"a": 1},
        )


def test_raw_event_missing_fields_and_internal_flag(raw_event):
    assert raw_event.source_is_internal is False
    event = RawEvent(event_id="e", source="edr", event_type="x", raw_log="hello")
    assert "user" in event.missing_fields
    assert RawEvent(
        event_id="e2",
        source="edr",
        event_type="x",
        source_ip="10.0.0.1",
        raw_payload={"k": 1},
    ).source_is_internal is True


# --------------------------------------------------------------------------
# Investigation
# --------------------------------------------------------------------------
def test_technique_ids_must_be_well_formed():
    MitreTechnique(technique_id="T1110.001", name="n", tactic="t")
    with pytest.raises(ValidationError, match="T1566"):
        MitreTechnique(technique_id="1110", name="n", tactic="t")


def test_investigation_rejects_blank_evidence():
    with pytest.raises(ValidationError, match="blank"):
        Investigation(
            incident_id="i",
            hypothesis="h",
            recommended_severity=Severity.LOW,
            evidence=["real", "   "],
        )


def test_enriched_ioc_shape():
    ioc = EnrichedIOC(indicator="8.8.8.8", reputation="unknown", source="local_intel")
    assert ioc.type is None
    with pytest.raises(ValidationError):
        EnrichedIOC(indicator="x", reputation="definitely evil", source="s")


# --------------------------------------------------------------------------
# PlaybookStep / ResponsePlan
# --------------------------------------------------------------------------
def test_destructive_step_requires_approval():
    with pytest.raises(ValidationError, match="requires_approval"):
        PlaybookStep(
            order=1,
            phase="containment",
            action="Isolate host dc01",
            requires_approval=False,
            justification="because",
        )


def test_step_cannot_be_automatable_and_gated():
    with pytest.raises(ValidationError, match="automatable"):
        PlaybookStep(
            order=1,
            phase="recovery",
            action="Rotate credentials on the segment",
            requires_approval=True,
            automatable=True,
            justification="wide impact",
        )


def test_jev_scores_force_approval_on_construction():
    step = PlaybookStep(
        order=1,
        phase="containment",
        action="Snapshot the volume",
        requires_approval=False,
        justification="forensics",
        blast_radius_score=2.0,
    )
    assert step.requires_approval is True and step.automatable is False
    step2 = PlaybookStep(
        order=1,
        phase="containment",
        action="Snapshot the volume",
        requires_approval=False,
        justification="forensics",
        hitl_noul=0.7,
    )
    assert step2.requires_approval is True


def test_plan_approval_flag_must_match_steps(response_plan, safe_step):
    with pytest.raises(ValidationError, match="requires_human_approval"):
        ResponsePlan(
            incident_id="i",
            planned_at=NOW,
            playbook_name="p",
            summary="s",
            steps=[safe_step],
            requires_human_approval=True,
            residual_risk="r",
        )
    assert response_plan.requires_human_approval is True


def test_plan_step_orders_must_be_unique(safe_step, destructive_step):
    twin = safe_step.model_copy(update={"order": 2})
    with pytest.raises(ValidationError, match="unique"):
        ResponsePlan(
            incident_id="i",
            planned_at=NOW,
            playbook_name="p",
            summary="s",
            steps=[twin, destructive_step],
            requires_human_approval=True,
            residual_risk="r",
        )


# --------------------------------------------------------------------------
# CaseReport
# --------------------------------------------------------------------------
def test_false_positive_cannot_carry_investigation(incident, investigation, raw_event):
    quiet = incident.model_copy(
        update={
            "escalate": False,
            "false_positive_reason": "noise",
        }
    )
    with pytest.raises(ValidationError, match="closed_false_positive"):
        CaseReport(
            incident_id="inc-0001",
            incident=quiet,
            investigation=investigation,
            final_state="closed_false_positive",
            generated_at=NOW,
        )


def test_false_positive_requires_unescalated_incident(incident, raw_event):
    with pytest.raises(ValidationError, match="escalate=False"):
        CaseReport(
            incident_id="inc-0001",
            incident=incident,  # escalate=True
            final_state="closed_false_positive",
            generated_at=NOW,
        )


def test_escalated_states_require_investigation(incident, raw_event):
    with pytest.raises(ValidationError, match="requires an investigation"):
        CaseReport(
            incident_id="inc-0001",
            incident=incident,
            final_state="escalated_to_human",
            generated_at=NOW,
        )


def test_report_ids_must_thread(incident, investigation, raw_event):
    with pytest.raises(ValidationError, match="must match"):
        CaseReport(
            incident_id="inc-9999",
            incident=incident,
            investigation=investigation,
            final_state="escalated_to_human",
            generated_at=NOW,
        )


def test_valid_report_round_trips(incident, investigation, response_plan, raw_event):
    report = CaseReport(
        incident_id="inc-0001",
        incident=incident,
        investigation=investigation,
        response_plan=response_plan,
        final_state="escalated_to_human",
        generated_at=NOW,
    )
    assert CaseReport.model_validate_json(report.model_dump_json()) == report
