"""Shared vocabulary for the inter-agent contracts.

Every agent boundary in this system is a Pydantic model, and the models share a
small vocabulary: the severity scale, the incident taxonomy, and the shape of an
observable (an IOC). Centralizing them here keeps `Incident`, `Investigation` and
`ResponsePlan` speaking exactly the same language, and gives one place to enforce
that — for example — an observable tagged `ip` actually holds a valid IP address.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, model_validator

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]

IncidentCategory = Literal[
    "phishing",
    "brute_force",
    "malware",
    "exfiltration",
    "lateral_movement",
    "recon",
    "other",
]

ObservableType = Literal["ip", "domain", "url", "sha256", "md5", "email", "filepath"]

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")


def is_internal_ip(ip: str | None) -> bool:
    """Return True if `ip` is a private (RFC 1918) address.

    Mirrors `is_internal_ip` in the SOC triage agent. A malformed or absent
    address is treated as "not internal", so callers never have to guard it.
    """
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def ensure_aware(value: datetime | None) -> datetime | None:
    """Coerce a datetime to timezone-aware UTC; pass None through.

    A naive datetime is interpreted as UTC rather than host-local time, so the
    same event parsed on two machines yields the same instant. Reused by every
    schema that carries a timestamp.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class Observable(BaseModel):
    """A single typed indicator of compromise (IOC).

    The type is not decorative: it is validated against the value, so an
    `Observable(type="ip", value="not-an-ip")` fails at construction rather than
    reaching threat-intel lookups that would silently return nothing.
    """

    type: ObservableType
    value: str = Field(min_length=1)
    context: str | None = None

    @model_validator(mode="after")
    def _check_value_matches_type(self) -> "Observable":
        if self.type == "ip":
            try:
                ipaddress.ip_address(self.value)
            except ValueError as exc:
                raise ValueError(f"not a valid IP address: {self.value!r}") from exc
        elif self.type == "sha256" and not _SHA256_RE.match(self.value):
            raise ValueError(f"not a valid SHA-256 hash: {self.value!r}")
        elif self.type == "md5" and not _MD5_RE.match(self.value):
            raise ValueError(f"not a valid MD5 hash: {self.value!r}")
        elif self.type == "email" and "@" not in self.value:
            raise ValueError(f"not a valid email address: {self.value!r}")
        return self
