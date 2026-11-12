"""Investigator output.

The investigator enriches an incident into a defensible hypothesis: which ATT&CK
techniques it maps to, what the observables' reputation says, and how confident
it is. Guardrails against hallucination are encoded here rather than trusted to
the prompt: every technique id must be well-formed (`T####[.YYYY]` style), and
any evidence items that are present cannot be blank. Verifying technique ids
against the real ATT&CK catalog happens in the investigator's validation hook;
grounding against the enriched intel is audited by Jev.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from orchestrator.schemas.common import (
    ObservableType,
    Reputation,
    Severity,
    ensure_aware,
)

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def _utcnow() -> datetime:
    return datetime.now(UTC)


class MitreTechnique(BaseModel):
    technique_id: str
    name: str = Field(min_length=1)
    tactic: str = Field(min_length=1)
    evidence: str | None = None

    @field_validator("technique_id")
    @classmethod
    def _well_formed(cls, value: str) -> str:
        if not _TECHNIQUE_RE.match(value):
            raise ValueError(
                f"technique_id must look like T1566 or T1566.001, got {value!r}"
            )
        return value


class EnrichedIOC(BaseModel):
    """One indicator after a threat-intel lookup (local or live)."""

    indicator: str = Field(min_length=1)
    type: ObservableType | None = None
    reputation: Reputation
    source: str = Field(min_length=1)
    detail: dict[str, Any] | None = None


class Investigation(BaseModel):
    incident_id: str = Field(min_length=1)
    investigated_at: datetime = Field(default_factory=_utcnow)
    hypothesis: str = Field(min_length=1)
    attack_chain_summary: str = ""
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    enriched_iocs: list[EnrichedIOC] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    recommended_severity: Severity
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)

    @field_validator("investigated_at")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value) or value

    @field_validator("evidence")
    @classmethod
    def _no_blank_evidence(cls, value: list[str]) -> list[str]:
        if any(not item.strip() for item in value):
            raise ValueError("evidence items must not be blank")
        return value
