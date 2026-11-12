"""Input contract: a raw security event as it arrives from a source.

`RawEvent` is the widest schema in the system — it accepts whatever a SIEM, EDR,
firewall or email gateway emits, with most fields optional because no single
source carries all of them. Everything downstream is progressively narrower and
stricter.

Field names follow the agent-facing vocabulary (`hostname`, `destination_ip`);
`validation_alias` keeps the historic SIEM spellings (`host`, `dest_ip`)
working so every bundled scenario parses unchanged. `raw_log` is optional
because structured sources ship `raw_payload` instead; at least one of the two
must carry content, otherwise there is nothing to triage.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, Field, field_validator, model_validator

from orchestrator.schemas.common import ensure_aware, is_internal_ip

SeverityHint = Literal["info", "low", "medium", "high", "critical"]


class RawEvent(BaseModel):
    event_id: str = Field(min_length=1)
    timestamp: datetime | None = None
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    severity_hint: SeverityHint | None = None
    source_ip: str | None = None
    destination_ip: str | None = Field(
        default=None, validation_alias=AliasChoices("destination_ip", "dest_ip")
    )
    hostname: str | None = Field(
        default=None, validation_alias=AliasChoices("hostname", "host")
    )
    user: str | None = None
    raw_log: str | None = None
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    observables: list[str] = Field(default_factory=list)

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def _check_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError(f"not a valid IP address: {value!r}") from exc
        return value

    @field_validator("timestamp")
    @classmethod
    def _ensure_aware(cls, value: datetime | None) -> datetime | None:
        return ensure_aware(value)

    @model_validator(mode="after")
    def _has_content(self) -> RawEvent:
        if not (self.raw_log and self.raw_log.strip()) and not self.raw_payload:
            raise ValueError(
                "a RawEvent must carry content in raw_log or raw_payload"
            )
        return self

    @property
    def source_is_internal(self) -> bool:
        return is_internal_ip(self.source_ip)

    @property
    def missing_fields(self) -> list[str]:
        """Names of the context fields this source did not provide."""
        candidates = {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "hostname": self.hostname,
            "user": self.user,
        }
        return [name for name, value in candidates.items() if value is None]
