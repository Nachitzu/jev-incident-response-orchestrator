"""Investigator output.

The investigator enriches an incident into a defensible hypothesis: which ATT&CK
techniques it maps to, what the observables' reputation says, and how confident it
is. Two guardrails against hallucination are encoded here rather than trusted to
the prompt: every technique id must be well-formed (`T####[.###]`), and the
hypothesis cannot stand without at least one piece of cited evidence. Verifying
technique ids against the real ATT&CK catalog happens in the investigator's tool
layer (Phase 2); this schema enforces the shape.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from src.orchestrator.schemas.common import Observable, Severity, ensure_aware

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

KillChainStage = Literal[
    "recon",
    "weaponization",
    "delivery",
    "exploitation",
    "installation",
    "command_and_control",
    "actions_on_objectives",
]

Reputation = Literal["malicious", "suspicious", "benign", "unknown"]


class MitreTechnique(BaseModel):
    technique_id: str
    name: str = Field(min_length=1)
    tactic: str = Field(min_length=1)

    @field_validator("technique_id")
    @classmethod
    def _well_formed(cls, value: str) -> str:
        if not _TECHNIQUE_RE.match(value):
            raise ValueError(
                f"technique_id must look like T1566 or T1566.001, got {value!r}"
            )
        return value


class EnrichedObservable(BaseModel):
    observable: Observable
    reputation: Reputation
    source: str = Field(min_length=1)
    detail: dict | None = None


class Investigation(BaseModel):
    incident_id: str = Field(min_length=1)
    investigated_at: datetime
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    enriched_observables: list[EnrichedObservable] = Field(default_factory=list)
    hypothesis: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    kill_chain_stage: KillChainStage
    evidence: list[str] = Field(min_length=1)
    recommended_severity: Severity

    @field_validator("investigated_at")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value)

    @field_validator("evidence")
    @classmethod
    def _no_blank_evidence(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("evidence items must not be blank")
        return value
