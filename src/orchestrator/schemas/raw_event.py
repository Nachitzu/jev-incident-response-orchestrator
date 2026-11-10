"""Input contract: a raw security event as it arrives from a source.

`RawEvent` is the widest schema in the system — it accepts whatever a SIEM, EDR,
firewall or email gateway emits, with most fields optional because no single
source carries all of them. Everything downstream is progressively narrower and
stricter. This mirrors `NormalizedAlert` from the SOC triage agent, extended with
the multi-source fields (`user`, `host`, free-form `observables`) the detector
needs to correlate events into an incident.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from src.orchestrator.schemas.common import ensure_aware, is_internal_ip

SeverityHint = Literal["info", "low", "medium", "high", "critical"]


class RawEvent(BaseModel):
    event_id: str = Field(min_length=1)
    timestamp: datetime | None = None
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    severity_hint: SeverityHint | None = None
    source_ip: str | None = None
    dest_ip: str | None = None
    user: str | None = None
    host: str | None = None
    raw_log: str
    observables: list[str] = Field(default_factory=list)

    @field_validator("source_ip", "dest_ip")
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

    @property
    def source_is_internal(self) -> bool:
        return is_internal_ip(self.source_ip)

    @property
    def missing_fields(self) -> list[str]:
        """Names of the context fields this source did not provide."""
        candidates = {
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "user": self.user,
            "host": self.host,
        }
        return [name for name, value in candidates.items() if value is None]
