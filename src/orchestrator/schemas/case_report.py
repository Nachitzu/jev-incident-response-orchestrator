"""Orchestrator output: the full auditable case file.

A `CaseReport` bundles the incident, the investigation and the response plan
together with the `AuditLog` — the ordered record of every decision each agent
made and the model that made it. This is the interpretability requirement from the
project brief: an analyst must be able to reconstruct *why* the system reached each
conclusion, not just what it concluded. The report serializes to JSON and renders
to Markdown (Phases 3–4).
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from src.orchestrator.schemas.common import ensure_aware
from src.orchestrator.schemas.incident import Incident
from src.orchestrator.schemas.investigation import Investigation
from src.orchestrator.schemas.response_plan import ResponsePlan

Stage = Literal["detection", "investigation", "response", "orchestration"]

FinalState = Literal[
    "closed_false_positive",
    "closed_resolved_suggested",
    "escalated_to_human",
]


class AuditEntry(BaseModel):
    timestamp: datetime
    stage: Stage
    agent: str = Field(min_length=1)
    model: str | None = None
    decision: str = Field(min_length=1)
    inputs_digest: str = Field(min_length=1)

    @field_validator("timestamp")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value)


class CaseReport(BaseModel):
    incident_id: str = Field(min_length=1)
    incident: Incident
    investigation: Investigation | None = None
    response_plan: ResponsePlan | None = None
    final_state: FinalState
    audit_log: list[AuditEntry] = Field(default_factory=list)
    generated_at: datetime

    @field_validator("generated_at")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @model_validator(mode="after")
    def _state_consistency(self) -> "CaseReport":
        # A false positive never advanced past detection.
        if self.final_state == "closed_false_positive":
            if self.investigation is not None or self.response_plan is not None:
                raise ValueError(
                    "closed_false_positive cannot carry an investigation or plan"
                )
        elif self.investigation is None:
            raise ValueError(
                f"final_state {self.final_state!r} requires an investigation"
            )

        # incident_id must thread through the whole case.
        if self.incident.incident_id != self.incident_id:
            raise ValueError("incident_id must match incident.incident_id")
        if self.investigation and self.investigation.incident_id != self.incident_id:
            raise ValueError("investigation.incident_id must match the case")
        if self.response_plan and self.response_plan.incident_id != self.incident_id:
            raise ValueError("response_plan.incident_id must match the case")
        return self
