"""Shared vocabulary for the inter-agent contracts.

Every agent boundary in this system is a Pydantic model, and the models share a
small vocabulary: the severity scale, the incident taxonomy, the shape of an
observable (an IOC), and the audit-trail entry each agent appends to. Enums
rather than ``Literal`` aliases: agents compare ``Severity.HIGH`` and construct
``IncidentCategory("phishing")`` directly, and serialized JSON keeps the same
spellings the schemas always used.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator


class Severity(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IncidentCategory(StrEnum):
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    EXFILTRATION = "exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    RECON = "recon"
    OTHER = "other"


SEVERITY_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class ObservableType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    MD5 = "md5"
    EMAIL = "email"
    FILEPATH = "filepath"


Reputation = Literal["malicious", "suspicious", "benign", "unknown"]

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")


def is_internal_ip(ip: str | None) -> bool:
    """Return True if `ip` is a private (RFC 1918) address.

    A malformed or absent address is treated as "not internal", so callers
    never have to guard it.
    """
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def guess_indicator_type(value: str) -> ObservableType:
    """Best-effort typing of a raw indicator string (ip/hash/url/email/filepath/domain)."""
    try:
        ipaddress.ip_address(value)
        return ObservableType.IP
    except ValueError:
        pass
    if _SHA256_RE.match(value):
        return ObservableType.SHA256
    if _MD5_RE.match(value):
        return ObservableType.MD5
    if value.startswith(("http://", "https://")):
        return ObservableType.URL
    if "@" in value:
        return ObservableType.EMAIL
    if "/" in value or "\\" in value:
        return ObservableType.FILEPATH
    return ObservableType.DOMAIN


def ensure_aware(value: datetime | None) -> datetime | None:
    """Coerce a datetime to timezone-aware UTC; pass None through.

    A naive datetime is interpreted as UTC rather than host-local time, so the
    same event parsed on two machines yields the same instant.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class Observable(BaseModel):
    """A single typed indicator of compromise (IOC).

    The type is validated against the value, so an
    `Observable(type="ip", value="not-an-ip")` fails at construction rather than
    reaching threat-intel lookups that would silently return nothing.
    """

    type: ObservableType
    value: str = Field(min_length=1)
    context: str | None = None

    @model_validator(mode="after")
    def _check_value_matches_type(self) -> Observable:
        if self.type == ObservableType.IP:
            try:
                ipaddress.ip_address(self.value)
            except ValueError as exc:
                raise ValueError(f"not a valid IP address: {self.value!r}") from exc
        elif self.type == ObservableType.SHA256 and not _SHA256_RE.match(self.value):
            raise ValueError(f"not a valid SHA-256 hash: {self.value!r}")
        elif self.type == ObservableType.MD5 and not _MD5_RE.match(self.value):
            raise ValueError(f"not a valid MD5 hash: {self.value!r}")
        elif self.type == ObservableType.EMAIL and "@" not in self.value:
            raise ValueError(f"not a valid email address: {self.value!r}")
        return self


class AuditEntry(BaseModel):
    """One auditable decision step, appended by an agent or the orchestrator.

    `stage` is a free-form namespaced label ("detect:short_circuit",
    "investigate:sde_cascade_escalated", ...) so agents can add steps without a
    central registry; `actor` says who decided (agent + model, or an engine
    name), `action` what it decided to do, `details` the numbers behind it.
    """

    timestamp: datetime
    stage: str = Field(min_length=1)
    actor: str = Field(min_length=1)
    action: str = Field(min_length=1)
    details: str = ""

    @field_validator("timestamp")
    @classmethod
    def _ensure_aware(cls, value: datetime) -> datetime:
        return ensure_aware(value) or value


class SystemOneTelemetry(BaseModel):
    """Telemetria auditable de las primitivas de Jev (Noul, Choice, Score)."""

    prompt_injection_noul: float | None = Field(default=None, ge=0.0, le=1.0)
    is_threat_noul: float | None = Field(default=None, ge=0.0, le=1.0)
    already_contained_noul: float | None = Field(default=None, ge=0.0, le=1.0)
    category_fits_noul: float | None = Field(default=None, ge=0.0, le=1.0)
    category_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    category_probabilities: dict[str, float] = Field(default_factory=dict)
    severity_score: float | None = Field(default=None, ge=0.0, le=3.0)
    severity_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    grounding_nouls: dict[str, float] = Field(default_factory=dict)
    escalated_by_cascade: bool = False
