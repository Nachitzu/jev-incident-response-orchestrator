"""Shared fixtures and offline doubles for the suite. No test reaches the network."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import pytest

from orchestrator.schemas import (
    Incident,
    IncidentCategory,
    Investigation,
    MitreTechnique,
    PlaybookStep,
    RawEvent,
    ResponsePlan,
    Severity,
)


@pytest.fixture(autouse=True)
def _offline_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A stray real key in the environment can never be used by a test."""
    for var in (
        "ANTHROPIC_API_KEY",
        "ABUSEIPDB_API_KEY",
        "TYPESAFE_API_KEY",
        "DEEPSEEK_API_KEY",
        "SOAR_LLM_PROVIDER",
        "SOAR_JEV_MODE",
        "SOAR_FP_NOUL_THRESHOLD",
        "SOAR_HITL_CONFIDENCE_MIN",
    ):
        monkeypatch.delenv(var, raising=False)


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
        destination_ip="10.0.1.12",
        hostname="dc01",
        user="admin",
        raw_log="47 failed SSH logins for 'admin' in 120s, then 1 success",
        observables=["185.220.101.34"],
    )


@pytest.fixture
def incident() -> Incident:
    return Incident(
        incident_id="inc-0001",
        source_event_id="evt-0001",
        title="Probable SSH brute-force compromise of a domain controller",
        summary="47 failed logins followed by a success against a critical asset.",
        severity=Severity.HIGH,
        category=IncidentCategory.BRUTE_FORCE,
        confidence=0.82,
        escalate=True,
        initial_indicators=["185.220.101.34"],
    )


@pytest.fixture
def investigation() -> Investigation:
    return Investigation(
        incident_id="inc-0001",
        hypothesis="External actor brute-forced SSH and gained an admin session.",
        attack_chain_summary="Credential access escalating into exploitation of a DC.",
        mitre_techniques=[
            MitreTechnique(
                technique_id="T1110.001",
                name="Password Guessing",
                tactic="Credential Access",
                evidence="47 failed logins then a success in 120s.",
            )
        ],
        affected_assets=["dc01"],
        recommended_severity=Severity.CRITICAL,
        confidence=0.78,
        evidence=["47 failed logins then success", "source IP is a known tor exit"],
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
def response_plan(safe_step: PlaybookStep, destructive_step: PlaybookStep) -> ResponsePlan:
    return ResponsePlan(
        incident_id="inc-0001",
        planned_at=datetime(2026, 7, 8, 3, 25, tzinfo=UTC),
        playbook_name="brute_force",
        summary="Contain the domain controller and rotate the admin credential.",
        steps=[safe_step, destructive_step],
        requires_human_approval=True,
        residual_risk="Lateral movement may already have occurred before isolation.",
    )


class FakeStructuredLLM:
    """Structured-client double that replays pre-built contract objects.

    A reply is either a model instance (returned after the agent's `validator`
    ran, so contract guards are exercised) or an exception (raised). Every call
    is recorded so tests can assert which model the cascade actually used.
    """

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def generate_structured(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        response_model: Any,
        validator: Any = None,
        toolbox: Any = None,
    ) -> Any:
        self.calls.append(
            {"model": model, "user_prompt": user_prompt, "response_model": response_model}
        )
        if not self._responses:
            raise AssertionError("FakeStructuredLLM ran out of scripted replies")
        result = self._responses.pop(0)
        if isinstance(result, Exception):
            raise result
        if not isinstance(result, response_model):
            raise TypeError(
                f"scripted reply {type(result).__name__} does not satisfy "
                f"{response_model.__name__}"
            )
        if validator is not None:
            validator(result)
        return result


@dataclass(frozen=True)
class FakeTriage:
    prompt_injection_prob: float = 0.02
    is_threat_prob: float = 0.10
    already_contained_prob: float = 0.05
    category_fits_prob: float = 0.90
    category: str = "recon"
    category_confidence: float = 0.88
    category_probabilities: dict[str, float] = field(default_factory=dict)
    severity_score: float = 0.15
    severity_label: str = "low"
    severity_confidence: float = 0.92
    requires_escalation: bool = False
    drop_reason: str | None = None


class FakeJev:
    """Jev double implementing the detector, investigator and responder protocols."""

    def __init__(
        self,
        triage: FakeTriage | None = None,
        grounding_checks: dict[str, float] | None = None,
        ranked_mitre: list[str] | None = None,
        playbook_choice: str | None = None,
        step_scores: list[tuple[float, float, float]] | None = None,
        enabled: bool = True,
        mode: str = "hybrid",
    ) -> None:
        self._triage = triage or FakeTriage()
        self._grounding = grounding_checks or {
            "grounded_in_iocs": 0.95,
            "mitre_coherent": 0.91,
            "no_speculation": 0.89,
        }
        self._ranked = ranked_mitre or ["T1110", "T1078"]
        self._playbook = playbook_choice
        self._step_scores = step_scores
        self._enabled = enabled
        self.mode = mode
        self.triage_calls = 0
        self.verify_calls = 0
        self.rank_calls = 0
        self.playbook_calls = 0
        self.score_calls = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    def evaluate_raw_event(self, raw_event: dict[str, Any]) -> FakeTriage:
        self.triage_calls += 1
        return self._triage

    def verify_investigation(
        self,
        incident_data: dict[str, Any],
        enriched_iocs: list[dict[str, Any]],
        investigation_draft: dict[str, Any],
    ) -> dict[str, float]:
        self.verify_calls += 1
        return self._grounding

    def rank_mitre_candidates(
        self,
        incident_data: dict[str, Any],
        candidates: list[dict[str, Any]],
        top_k: int = 5,
    ) -> list[str]:
        self.rank_calls += 1
        return self._ranked[:top_k]

    def select_playbook(
        self,
        incident_data: dict[str, Any],
        investigation_data: dict[str, Any],
        playbooks: dict[str, dict[str, Any]],
    ) -> str:
        self.playbook_calls += 1
        return self._playbook or incident_data["category"]

    def score_response_steps(
        self,
        incident_data: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> list[tuple[float, float, float]]:
        self.score_calls += 1
        if self._step_scores is not None:
            return self._step_scores[: len(steps)]
        return [(0.2, 1.0, 0.9) for _ in steps]
