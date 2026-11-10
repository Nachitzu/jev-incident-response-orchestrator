"""Shared fixtures for the contract tests. No test here reaches the network."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest

from src.orchestrator.schemas import (
    AuditEntry,
    Incident,
    Investigation,
    MitreTechnique,
    Observable,
    PlaybookStep,
    RawEvent,
    ResponsePlan,
)

UTC = timezone.utc


@pytest.fixture
def observable_ip() -> Observable:
    return Observable(type="ip", value="185.220.101.34", context="known tor exit")


@pytest.fixture
def raw_event() -> RawEvent:
    """A complete brute-force event against a domain controller."""
    return RawEvent(
        event_id="evt-0001",
        timestamp="2026-07-08T03:12:44Z",
        source="EDR",
        event_type="authentication_failure_burst",
        severity_hint="high",
        source_ip="185.220.101.34",
        dest_ip="10.0.1.12",
        user="admin",
        host="dc01",
        raw_log="47 failed SSH logins for 'admin' in 120s, then 1 success",
        observables=["185.220.101.34"],
    )


@pytest.fixture
def incident(observable_ip: Observable) -> Incident:
    return Incident(
        incident_id="inc-0001",
        created_at=datetime(2026, 7, 8, 3, 13, tzinfo=UTC),
        triggering_events=["evt-0001"],
        title="Probable SSH brute-force compromise of a domain controller",
        category="brute_force",
        severity="HIGH",
        detection_confidence=0.82,
        rationale="47 failed logins followed by a success against a critical asset",
        observables=[observable_ip],
    )


@pytest.fixture
def mitre_technique() -> MitreTechnique:
    return MitreTechnique(
        technique_id="T1110.001", name="Password Guessing", tactic="Credential Access"
    )


@pytest.fixture
def investigation(mitre_technique: MitreTechnique) -> Investigation:
    return Investigation(
        incident_id="inc-0001",
        investigated_at=datetime(2026, 7, 8, 3, 20, tzinfo=UTC),
        mitre_techniques=[mitre_technique],
        hypothesis="External actor brute-forced SSH and gained an admin session.",
        confidence=0.78,
        kill_chain_stage="exploitation",
        evidence=["47 failed logins then success", "source IP is a known tor exit"],
        recommended_severity="CRITICAL",
    )


@pytest.fixture
def safe_step() -> PlaybookStep:
    return PlaybookStep(
        order=1,
        phase="containment",
        action="Open a Tier 2 ticket and notify the on-call analyst",
        requires_approval=False,
        automatable=True,
        justification="Non-destructive notification; safe to automate",
    )


@pytest.fixture
def destructive_step() -> PlaybookStep:
    return PlaybookStep(
        order=2,
        phase="containment",
        action="Isolate host dc01 from the network",
        requires_approval=True,
        automatable=False,
        justification="Network isolation is disruptive to a critical asset",
    )


@pytest.fixture
def response_plan(
    safe_step: PlaybookStep, destructive_step: PlaybookStep
) -> ResponsePlan:
    return ResponsePlan(
        incident_id="inc-0001",
        planned_at=datetime(2026, 7, 8, 3, 25, tzinfo=UTC),
        playbook_name="brute_force",
        summary="Contain the domain controller and rotate the admin credential.",
        steps=[safe_step, destructive_step],
        requires_human_approval=True,
        residual_risk="Lateral movement may already have occurred before isolation.",
    )


@pytest.fixture
def audit_entry() -> AuditEntry:
    return AuditEntry(
        timestamp=datetime(2026, 7, 8, 3, 13, tzinfo=UTC),
        stage="detection",
        agent="DetectorAgent",
        model="claude-haiku-4-5",
        decision="escalate",
        inputs_digest="1 event, brute_force signature on dc01",
    )


@pytest.fixture(autouse=True)
def _no_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stray real key in the environment can never be used by a test."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("SOAR_MODEL", raising=False)


# --------------------------------------------------------------------------
# Offline doubles for the Anthropic client and the toolbox
# --------------------------------------------------------------------------
@dataclass
class FakeBlock:
    """One content block, shaped like the SDK's but built by hand."""

    type: str
    text: str | None = None
    name: str | None = None
    input: dict | None = None
    id: str | None = None


@dataclass
class FakeResponse:
    content: list[FakeBlock]


def text_block(text: str) -> FakeBlock:
    return FakeBlock(type="text", text=text)


def tool_use_block(name: str, arguments: dict, block_id: str = "tu-1") -> FakeBlock:
    return FakeBlock(type="tool_use", name=name, input=arguments, id=block_id)


class FakeClient:
    """Replays a scripted list of replies instead of calling the API.

    A reply is either a string (turned into a single text block) or a list of
    blocks, which is how a tool-use turn is expressed. Every request is recorded
    in `calls`, so a test can assert on the model, the tools, and the retry
    messages the agent actually sent.
    """

    def __init__(self, replies: list) -> None:
        self._replies = list(replies)
        self.calls: list[dict] = []

    @property
    def messages(self):  # mirrors client.messages.create(...)
        return self

    def create(self, **kwargs) -> FakeResponse:
        self.calls.append(kwargs)
        if not self._replies:
            raise AssertionError("FakeClient ran out of scripted replies")
        reply = self._replies.pop(0)
        if isinstance(reply, str):
            return FakeResponse(content=[text_block(reply)])
        return FakeResponse(content=list(reply))


class FakeToolbox:
    """A toolbox whose answers are fixed, to isolate an agent from the data set."""

    def __init__(self, results: dict[str, dict] | None = None) -> None:
        self.results = results or {}
        self.calls: list[tuple[str, dict]] = []

    @property
    def definitions(self) -> list[dict]:
        return [
            {
                "name": name,
                "description": "fake",
                "input_schema": {"type": "object", "properties": {}},
            }
            for name in self.results
        ]

    def dispatch(self, name: str, arguments: dict) -> tuple[str, bool]:
        self.calls.append((name, arguments))
        if name not in self.results:
            return json.dumps({"error": f"unknown tool {name!r}"}), True
        return json.dumps(self.results[name]), False
