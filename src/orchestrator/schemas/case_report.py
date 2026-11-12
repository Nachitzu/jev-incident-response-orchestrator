"""Orchestrator output: the full auditable case file.

A `CaseReport` bundles the incident, the investigation and the response plan
together with the audit log — the ordered record of every decision each agent
made and who made it. This is the interpretability requirement from the project
brief: an analyst must be able to reconstruct *why* the system reached each
conclusion, not just what it concluded.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from orchestrator.schemas.common import AuditEntry, ensure_aware
from orchestrator.schemas.incident import Incident
from orchestrator.schemas.investigation import Investigation
from orchestrator.schemas.response_plan import ResponsePlan

FinalState = Literal[
    "closed_false_positive",
    "closed_resolved_suggested",
    "escalated_to_human",
]

__all__ = ["AuditEntry", "CaseReport", "FinalState"]


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
        return ensure_aware(value) or value

    @model_validator(mode="after")
    def _state_consistency(self) -> CaseReport:
        # A false positive never advanced past detection, and a case the
        # detector dismissed cannot claim it escalated.
        if self.final_state == "closed_false_positive":
            if self.investigation is not None or self.response_plan is not None:
                raise ValueError(
                    "closed_false_positive cannot carry an investigation or plan"
                )
            if self.incident.escalate:
                raise ValueError(
                    "closed_false_positive requires incident.escalate=False"
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
