"""Responder output.

The response plan is a *suggestion*, never an execution — v1 of this system does
not touch a single host. The schema encodes the blue-team maturity rule that makes
that safe: any known-destructive action (isolate a host, disable an account, block
an IP, wipe a disk) MUST be flagged for human approval, and an action safe enough
to automate cannot simultaneously claim to be destructive. These invariants are the
whole point of the human-in-the-loop design, so they live in Pydantic where a model
cannot forget them.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from src.orchestrator.schemas.common import ensure_aware

Phase = Literal["containment", "eradication", "recovery"]

# Action keywords that are inherently destructive / disruptive. Any step whose
# `action` mentions one of these must require human approval. Matched as
# case-insensitive substrings so "Isolate the host" and "isolate_host" both hit.
DESTRUCTIVE_MARKERS = frozenset(
    {
        "isolate",
        "quarantine",
        "disable",
        "block",
        "wipe",
        "delete",
        "reimage",
        "shutdown",
        "kill process",
        "revoke",
        "reset password",
    }
)


class PlaybookStep(BaseModel):
    order: int = Field(ge=1)
    phase: Phase
    action: str = Field(min_length=1)
    requires_approval: bool
    automatable: bool = False
    justification: str = Field(min_length=1)
    blast_radius_score: float | None = Field(default=None, ge=0.0, le=3.0)
    hitl_noul: float | None = Field(default=None, ge=0.0, le=1.0)

    @property
    def is_destructive(self) -> bool:
        lowered = self.action.lower()
        return any(marker in lowered for marker in DESTRUCTIVE_MARKERS)

    @model_validator(mode="after")
    def _enforce_hitl(self) -> "PlaybookStep":
        if (
            self.blast_radius_score is not None
            and self.blast_radius_score >= 1.5
        ) or (self.hitl_noul is not None and self.hitl_noul >= 0.50):
            self.requires_approval = True
            self.automatable = False
        if self.is_destructive and not self.requires_approval:
            raise ValueError(f"destructive action {self.action!r} must set requires_approval=True")
        if self.automatable and self.requires_approval:
            raise ValueError(
                f"action {self.action!r} cannot be both automatable and require "
                "approval; automation is reserved for safe, non-destructive steps"
            )
        return self


class ResponsePlan(BaseModel):
    incident_id: str = Field(min_length=1)
    planned_at: datetime
    playbook_name: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    steps: list[PlaybookStep] = Field(min_length=1)
    requires_human_approval: bool
    residual_risk: str = Field(min_length=1)

    @field_validator("planned_at")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @model_validator(mode="after")
    def _approval_flag_matches_steps(self) -> "ResponsePlan":
        expected = any(step.requires_approval for step in self.steps)
        if self.requires_human_approval != expected:
            raise ValueError(
                "requires_human_approval must equal any(step.requires_approval): "
                f"expected {expected}, got {self.requires_human_approval}"
            )
        orders = [step.order for step in self.steps]
        if len(set(orders)) != len(orders):
            raise ValueError("step 'order' values must be unique")
        return self
