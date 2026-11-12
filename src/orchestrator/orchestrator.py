"""The incident state machine that drives the three agents.

The orchestrator owns everything the agents deliberately do not: which stage
runs next, what the case's final state is, and the audit trail. Agents stay
pure functions over contracts; the sequencing lives here, in one readable place.

    detected ──drop──► closed_false_positive
       │ escalate
       ▼
    investigating ──► response_suggested ──► escalated_to_human
                                          └► closed_resolved_suggested

A dropped scenario still produces a full `CaseReport`. "We decided this was
noise, and here is why" is an auditable outcome, not silence.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from orchestrator._llm import LLMError, StructuredLLMClient
from orchestrator.agents import DetectorAgent, InvestigatorAgent, ResponderAgent
from orchestrator.schemas import (
    SEVERITY_ORDER,
    AuditEntry,
    CaseReport,
    Incident,
    RawEvent,
)


class OrchestratorError(RuntimeError):
    """A case could not be carried through the pipeline."""


def load_events(path: str | Path) -> list[RawEvent]:
    """Read a scenario file (a JSON array of raw events) into `RawEvent`s."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list) or not raw:
        raise OrchestratorError(f"{path}: expected a non-empty JSON array of events")
    try:
        return [RawEvent.model_validate(item) for item in raw]
    except ValidationError as exc:
        raise OrchestratorError(f"{path}: invalid RawEvent:\n{exc}") from exc


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def run_case(
    events: list[RawEvent],
    *,
    llm_client: StructuredLLMClient | None = None,
    jev_engine: Any | None = None,
    incident_id: str | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> CaseReport:
    """Run one scenario end to end and return its case report.

    Every event is triaged; if more than one escalates, the highest-severity
    (then highest-confidence) one carries the case. `incident_id` only renames
    a dropped case (where no agent ever named a real incident); escalated cases
    keep the id the detector actually reasoned about.
    """
    if not events:
        raise OrchestratorError("run_case() needs at least one event")

    llm = llm_client or StructuredLLMClient()
    audit: list[AuditEntry] = []

    detector = DetectorAgent(
        llm_client=llm,
        jev_engine=jev_engine,
        fp_noul_threshold=_env_float("SOAR_FP_NOUL_THRESHOLD", 0.25),
        confidence_floor=_env_float("SOAR_HITL_CONFIDENCE_MIN", 0.70),
    )

    triaged: list[tuple[RawEvent, Incident]] = []
    try:
        for event in events:
            incident, entries = detector.run(event)
            audit.extend(entries)
            triaged.append((event, incident))
    except LLMError as exc:
        raise OrchestratorError(f"detection failed: {exc}") from exc

    escalated = [(ev, inc) for ev, inc in triaged if inc.escalate]

    if not escalated:
        _, dropped = triaged[0]
        final_incident = dropped
        if incident_id is not None and incident_id != dropped.incident_id:
            data = dropped.model_dump(mode="json")
            data["incident_id"] = incident_id
            final_incident = Incident.model_validate(data)
        audit.append(
            AuditEntry(
                timestamp=now(),
                stage="orchestration",
                actor="Orchestrator",
                action="closed_false_positive",
                details=(
                    f"no investigation performed for {final_incident.incident_id}"
                ),
            )
        )
        return CaseReport(
            incident_id=final_incident.incident_id,
            incident=final_incident,
            final_state="closed_false_positive",
            audit_log=audit,
            generated_at=now(),
        )

    event, incident = max(
        escalated,
        key=lambda item: (SEVERITY_ORDER[item[1].severity], item[1].confidence),
    )
    audit.append(
        AuditEntry(
            timestamp=now(),
            stage="orchestration",
            actor="Orchestrator",
            action="escalate",
            details=(
                f"incident {incident.incident_id} ({incident.severity}, "
                f"confidence {incident.confidence:.2f})"
            ),
        )
    )

    investigator = InvestigatorAgent(llm_client=llm, jev_engine=jev_engine)
    try:
        investigation, inv_audit = investigator.run(incident, event)
    except LLMError as exc:
        raise OrchestratorError(f"investigation failed: {exc}") from exc
    if investigation.incident_id != incident.incident_id:
        raise OrchestratorError(
            f"investigation incident_id {investigation.incident_id!r} drifted from "
            f"{incident.incident_id!r}"
        )
    audit.extend(inv_audit)

    responder = ResponderAgent(llm_client=llm, jev_engine=jev_engine)
    try:
        plan, resp_audit = responder.run(incident, investigation)
    except LLMError as exc:
        raise OrchestratorError(f"response planning failed: {exc}") from exc
    audit.extend(resp_audit)

    # The approval flag decides the terminal state: anything a human must sign
    # off on — or that Jev flagged as low-confidence — leaves the case open on
    # their desk, never auto-closed.
    needs_review = any(
        entry.stage == "detect:low_confidence_score" for entry in audit
    )
    final_state = (
        "escalated_to_human"
        if plan.requires_human_approval or needs_review
        else "closed_resolved_suggested"
    )
    audit.append(
        AuditEntry(
            timestamp=now(),
            stage="orchestration",
            actor="Orchestrator",
            action=final_state,
            details="plan suggested, nothing executed",
        )
    )

    return CaseReport(
        incident_id=incident.incident_id,
        incident=incident,
        investigation=investigation,
        response_plan=plan,
        final_state=final_state,
        audit_log=audit,
        generated_at=now(),
    )
