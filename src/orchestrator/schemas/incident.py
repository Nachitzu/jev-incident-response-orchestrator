"""Detector output / Investigator input.

The detector's job is to decide what deserves human-grade investigation. It emits
a `DetectionResult`: either an escalation carrying a structured `Incident`, or a
drop with a stated reason. The escalation rules live in the schema, not the
prompt — a detector that marks something CRITICAL without the confidence to back
it up produces a validation error, exactly as `TriageOutput` enforces its own
rules in the SOC triage agent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from src.orchestrator.schemas.common import (
    IncidentCategory,
    Observable,
    Severity,
    SystemOneTelemetry,
    ensure_aware,
)


class Incident(BaseModel):
    incident_id: str = Field(min_length=1)
    created_at: datetime
    triggering_events: list[str] = Field(min_length=1)
    title: str = Field(min_length=1)
    category: IncidentCategory
    severity: Severity
    detection_confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1)
    observables: list[Observable] = Field(default_factory=list)
    system_one_telemetry: SystemOneTelemetry | None = None
    status: Literal["detected"] = "detected"

    @field_validator("created_at")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @model_validator(mode="after")
    def _high_severity_needs_confidence(self) -> "Incident":
        # A CRITICAL/HIGH escalation commits Tier 2 time; it must be backed by at
        # least even-odds confidence, never raised "just in case".
        if self.severity in ("CRITICAL", "HIGH") and self.detection_confidence < 0.5:
            raise ValueError(
                f"{self.severity} incidents require detection_confidence >= 0.5, "
                f"got {self.detection_confidence}"
            )
        return self


class DetectionResult(BaseModel):
    """What the detector returns for one scenario: escalate or drop.

    Keeping the drop path first-class (with its own reason) is what makes the
    detector auditable: a dropped event is a decision on the record, not silence.
    """

    escalate: bool
    incident: Incident | None = None
    drop_reason: str | None = None

    @model_validator(mode="after")
    def _consistent(self) -> "DetectionResult":
        if self.escalate and self.incident is None:
            raise ValueError("escalate=True requires an incident")
        if not self.escalate and self.incident is not None:
            raise ValueError("escalate=False must not carry an incident")
        if not self.escalate and not (self.drop_reason and self.drop_reason.strip()):
            raise ValueError("a dropped event must state a drop_reason")
        return self
