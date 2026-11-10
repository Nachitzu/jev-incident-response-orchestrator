"""The incident state machine that drives the three agents.

The orchestrator owns everything the agents deliberately do not: which stage runs
next, what the case's final state is, and the audit trail. Agents stay pure
functions over contracts; the sequencing lives here, in one readable place.

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from pydantic import ValidationError

from src.orchestrator import _llm
from src.orchestrator.agents import detect, investigate, respond
from src.orchestrator.schemas import (
    AuditEntry,
    CaseReport,
    Incident,
    RawEvent,
)
from src.orchestrator.tools.toolbox import (
    INVESTIGATOR_TOOLS,
    RESPONDER_TOOLS,
    Toolbox,
)

UTC = timezone.utc


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


def _digest(events: list[RawEvent]) -> str:
    """A one-line description of what a stage was given, for the audit log."""
    sources = sorted({e.source for e in events})
    return f"{len(events)} event(s) from {', '.join(sources)}"


def _dropped_incident(
    events: list[RawEvent], incident_id: str, reason: str, now: datetime
) -> Incident:
    """Record a drop as a first-class incident row.

    `CaseReport` requires an incident, and that is the right constraint: a case
    that was closed as a false positive still needs a subject, a timestamp and a
    stated rationale, otherwise the decision is unreviewable.
    """
    return Incident(
        incident_id=incident_id,
        created_at=now,
        triggering_events=[e.event_id for e in events],
        title="No incident — dropped by the detector",
        category="other",
        severity="LOW",
        detection_confidence=0.0,
        rationale=reason,
    )


def run_case(
    events: list[RawEvent],
    *,
    client: Any,
    incident_id: str | None = None,
    detector_model: str = _llm.DETECTOR_MODEL,
    investigator_model: str = _llm.INVESTIGATOR_MODEL,
    responder_model: str = _llm.RESPONDER_MODEL,
    investigator_toolbox: Toolbox | None = None,
    responder_toolbox: Toolbox | None = None,
    jev_engine: Any | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> CaseReport:
    """Run one scenario end to end and return its case report.

    `incident_id` is only a fallback for a dropped case (where no agent ever
    named one); when the detector escalates, its own id wins so the id in the
    report is the one the model reasoned about.
    """
    if not events:
        raise OrchestratorError("run_case() needs at least one event")

    audit: list[AuditEntry] = []
    started = now()

    try:
        detection = detect(
            events, client=client, model=detector_model, jev_engine=jev_engine
        )
    except _llm.LLMError as exc:
        raise OrchestratorError(f"detection failed: {exc}") from exc

    detection_decision = (
        f"escalate: {detection.incident.title}"
        if detection.escalate and detection.incident is not None
        else f"drop: {detection.drop_reason}"
    )
    if (
        detection.incident is not None
        and "Prompt-injection alert" in detection.incident.rationale
    ):
        detection_decision += " [PROMPT-INJECTION ALERT: payload severity override blocked]"

    audit.append(
        AuditEntry(
            timestamp=now(),
            stage="detection",
            agent="DetectorAgent",
            model=detector_model,
            decision=detection_decision,
            inputs_digest=_digest(events),
        )
    )

    if not detection.escalate:
        incident = _dropped_incident(
            events,
            incident_id or f"case-{started:%Y%m%dT%H%M%S}",
            detection.drop_reason or "no reason recorded",
            started,
        )
        audit.append(
            AuditEntry(
                timestamp=now(),
                stage="orchestration",
                agent="Orchestrator",
                decision="closed_false_positive: no investigation performed",
                inputs_digest=f"detector drop for {incident.incident_id}",
            )
        )
        return CaseReport(
            incident_id=incident.incident_id,
            incident=incident,
            final_state="closed_false_positive",
            audit_log=audit,
            generated_at=now(),
        )

    incident = detection.incident
    assert incident is not None  # guaranteed by DetectionResult's validator

    inv_toolbox = investigator_toolbox or Toolbox(names=INVESTIGATOR_TOOLS)
    try:
        investigation = investigate(
            incident,
            client=client,
            model=investigator_model,
            toolbox=inv_toolbox,
            jev_engine=jev_engine,
        )
    except _llm.LLMError as exc:
        raise OrchestratorError(f"investigation failed: {exc}") from exc

    techniques = ", ".join(t.technique_id for t in investigation.mitre_techniques)
    audit.append(
        AuditEntry(
            timestamp=now(),
            stage="investigation",
            agent="InvestigatorAgent",
            model=investigator_model,
            decision=(
                f"{investigation.kill_chain_stage}; "
                f"severity {investigation.recommended_severity}; "
                f"ATT&CK {techniques or 'none verified'}"
            ),
            inputs_digest=(
                f"incident {incident.incident_id}, "
                f"{len(incident.observables)} observable(s), "
                f"{len(inv_toolbox.calls)} tool call(s)"
            ),
        )
    )

    resp_toolbox = responder_toolbox or Toolbox(names=RESPONDER_TOOLS)
    try:
        plan = respond(
            incident,
            investigation,
            client=client,
            model=responder_model,
            toolbox=resp_toolbox,
        )
    except _llm.LLMError as exc:
        raise OrchestratorError(f"response planning failed: {exc}") from exc

    approvals = sum(1 for step in plan.steps if step.requires_approval)
    audit.append(
        AuditEntry(
            timestamp=now(),
            stage="response",
            agent="ResponderAgent",
            model=responder_model,
            decision=(
                f"{plan.playbook_name}: {len(plan.steps)} step(s), "
                f"{approvals} needing approval"
            ),
            inputs_digest=f"incident {incident.incident_id} + investigation",
        )
    )

    # The approval flag decides the terminal state: anything a human must sign
    # off on leaves the case open on their desk, never auto-closed.
    final_state = (
        "escalated_to_human"
        if plan.requires_human_approval
        else "closed_resolved_suggested"
    )
    audit.append(
        AuditEntry(
            timestamp=now(),
            stage="orchestration",
            agent="Orchestrator",
            decision=f"{final_state}: plan suggested, nothing executed",
            inputs_digest=f"plan for {incident.incident_id}",
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
