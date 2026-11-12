"""Detector output / Investigator input.

The detector's job is to decide what deserves human-grade investigation. It
emits an `Incident` whose `escalate` flag carries the decision: escalate to the
investigator, or dismiss with a stated `false_positive_reason`. The rules live
in the schema, not the prompt — a detector that marks something CRITICAL
without the confidence to back it up, or dismisses an event without a reason,
produces a validation error and gets another attempt.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field, field_validator, model_validator

from orchestrator.schemas.common import (
    IncidentCategory,
    Severity,
    SystemOneTelemetry,
    ensure_aware,
)


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Incident(BaseModel):
    incident_id: str = Field(min_length=1)
    source_event_id: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    severity: Severity
    category: IncidentCategory
    confidence: float = Field(ge=0.0, le=1.0)
    escalate: bool
    false_positive_reason: str | None = None
    initial_indicators: list[str] = Field(default_factory=list)
    system_one_telemetry: SystemOneTelemetry | None = None

    @field_validator("created_at")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value) or value

    @model_validator(mode="after")
    def _decisions_are_justified(self) -> Incident:
        # A CRITICAL/HIGH escalation commits Tier 2 time; it must be backed by
        # at least even-odds confidence, never raised "just in case".
        if (
            self.escalate
            and self.severity in (Severity.HIGH, Severity.CRITICAL)
            and self.confidence < 0.5
        ):
            raise ValueError(
                f"{self.severity} incidents require confidence >= 0.5, "
                f"got {self.confidence}"
            )
        # A dismissal is a decision on the record, not silence.
        if not self.escalate and not (
            self.false_positive_reason and self.false_positive_reason.strip()
        ):
            raise ValueError(
                "an incident with escalate=False must state a false_positive_reason"
            )
        return self
