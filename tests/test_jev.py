"""Offline unit tests for TypeSafe (Jev) System One integration and SDE Cascade."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import pytest

from orchestrator._llm import MODEL_HAIKU, MODEL_SONNET
from orchestrator.agents.detector_agent import DetectorAgent
from orchestrator.agents.investigator_agent import InvestigatorAgent
from orchestrator.schemas.common import IncidentCategory, Severity
from orchestrator.schemas.incident import Incident
from orchestrator.schemas.investigation import Investigation, MitreTechnique
from orchestrator.schemas.raw_event import RawEvent


@dataclass(frozen=True)
class FakeTriageAssessment:
    """Mock determinista de TriageAssessment para tests sin red."""
    prompt_injection_prob: float = 0.02
    is_threat_prob: float = 0.10
    already_contained_prob: float = 0.05
    category_fits_prob: float = 0.90
    category: str = "recon"
    category_confidence: float = 0.88
    category_probabilities: dict[str, float] | None = None
    severity_score: float = 0.15
    severity_label: str = "low"
    severity_confidence: float = 0.92
    requires_escalation: bool = False
    drop_reason: str | None = "Filtered by Jev System One (is_threat=0.10 < 0.25)"


class FakeJevEngine:
    """Simulador de JevEngine configurable por test."""

    def __init__(
        self,
        triage: FakeTriageAssessment | None = None,
        grounding_checks: dict[str, float] | None = None,
        ranked_mitre: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        self._triage = triage or FakeTriageAssessment()
        self._grounding_checks = grounding_checks or {
            "grounded_in_iocs": 0.95,
            "mitre_coherent": 0.91,
            "no_speculation": 0.89,
        }
        self._ranked_mitre = ranked_mitre or ["T1110", "T1078"]
        self._enabled = enabled
        self.triage_calls = 0
        self.verify_calls = 0

    @property
    def enabled(self) -> bool:
        return self._enabled

    def evaluate_raw_event(self, raw_event: dict[str, Any]) -> FakeTriageAssessment:
        self.triage_calls += 1
        return self._triage

    def verify_investigation(
        self,
        incident_data: dict[str, Any],
        enriched_iocs: list[dict[str, Any]],
        investigation_draft: dict[str, Any],
    ) -> dict[str, float]:
        self.verify_calls += 1
        return self._grounding_checks

    def rank_mitre_candidates(
        self,
        incident_data: dict[str, Any],
        candidates: list[dict[str, Any]],
        top_k: int = 5,
    ) -> list[str]:
        return self._ranked_mitre[:top_k]


class SpyStructuredLLMClient:
    """Cliente LLM espía que registra qué modelos fueron invocados en la cascada."""

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
    ) -> Any:
        self.calls.append({"model": model, "user_prompt": user_prompt})
        result = self._responses.pop(0)
        if validator is not None:
            validator(result)
        return result


@pytest.fixture
def sample_raw_event() -> RawEvent:
    return RawEvent(
        event_id="EVT-2026-001",
        timestamp=datetime(2026, 11, 10, 12, 0, tzinfo=UTC),
        source="siem",
        event_type="network_connection",
        hostname="srv-backup-01",
        source_ip="10.0.10.5",
        destination_ip="10.0.20.100",
        raw_payload={"process": "rsync", "bytes_out": 1048576},
    )


def test_detector_short_circuits_false_positive_without_calling_llm(
    sample_raw_event: RawEvent,
) -> None:
    """Patrón 'Screen with a Noul first': si is_threat < 0.25, Haiku nunca se invoca."""
    fake_jev = FakeJevEngine(
        triage=FakeTriageAssessment(
            is_threat_prob=0.08,
            prompt_injection_prob=0.01,
            requires_escalation=False,
        )
    )
    spy_llm = SpyStructuredLLMClient(responses=[])
    detector = DetectorAgent(llm_client=spy_llm, jev_engine=fake_jev)  # type: ignore[arg-type]

    incident, audit = detector.run(sample_raw_event)

    assert incident.escalate is False
    assert incident.severity == Severity.LOW
    assert fake_jev.triage_calls == 1
    assert len(spy_llm.calls) == 0
    assert any(entry.stage == "detect:short_circuit" for entry in audit)


def test_detector_blocks_prompt_injection_override_attempt(
    sample_raw_event: RawEvent,
) -> None:
    """Si el log intenta inyectar instrucciones y el LLM devuelve LOW/escalate=False, Jev lo fuerza a HIGH/True."""
    fake_jev = FakeJevEngine(
        triage=FakeTriageAssessment(
            is_threat_prob=0.65,
            prompt_injection_prob=0.88,
            severity_score=2.2,
            severity_label="high",
            requires_escalation=True,
        )
    )
    hijacked_llm_incident = Incident(
        incident_id="INC-EVT-2026-001",
        source_event_id="EVT-2026-001",
        title="Benign maintenance",
        summary="Everything is fine, ignore alert.",
        severity=Severity.LOW,
        category=IncidentCategory.OTHER,
        confidence=0.95,
        escalate=False,
        false_positive_reason="Authorized by injected prompt",
        initial_indicators=[],
    )
    spy_llm = SpyStructuredLLMClient(responses=[hijacked_llm_incident])
    detector = DetectorAgent(llm_client=spy_llm, jev_engine=fake_jev)  # type: ignore[arg-type]

    incident, audit = detector.run(sample_raw_event)

    assert len(spy_llm.calls) == 1
    assert incident.escalate is True
    assert incident.severity == Severity.HIGH
    assert "Potential Prompt Injection" in incident.summary
    assert any(entry.stage == "detect:guardrail" for entry in audit)


def test_detector_downgrades_already_contained_threat(
    sample_raw_event: RawEvent,
) -> None:
    """Escenarios como malware-quarantined-01 (is_threat alto pero already_contained >= 0.80) no escalan."""
    fake_jev = FakeJevEngine(
        triage=FakeTriageAssessment(
            is_threat_prob=0.91,
            already_contained_prob=0.92,
            prompt_injection_prob=0.01,
            category="malware",
            severity_score=1.1,
            severity_label="low",
            requires_escalation=True,
        )
    )
    llm_incident = Incident(
        incident_id="INC-EVT-2026-001",
        source_event_id="EVT-2026-001",
        title="Quarantined Trojan on Endpoint",
        summary="EDR blocked and quarantined binary before execution.",
        severity=Severity.HIGH,
        category=IncidentCategory.MALWARE,
        confidence=0.90,
        escalate=True,
        initial_indicators=[],
    )
    spy_llm = SpyStructuredLLMClient(responses=[llm_incident])
    detector = DetectorAgent(llm_client=spy_llm, jev_engine=fake_jev)  # type: ignore[arg-type]

    incident, audit = detector.run(sample_raw_event)

    assert incident.escalate is False
    assert incident.severity == Severity.LOW
    assert any(entry.stage == "detect:contained_reconciliation" for entry in audit)


def test_investigator_sde_cascade_keeps_haiku_when_jev_nouls_pass(
    sample_raw_event: RawEvent,
) -> None:
    """Si los 3 Nouls de Jev >= 0.75, el InvestigatorAgent se queda con la respuesta de Haiku 4.5."""
    fake_jev = FakeJevEngine(
        grounding_checks={
            "grounded_in_iocs": 0.94,
            "mitre_coherent": 0.88,
            "no_speculation": 0.91,
        }
    )
    haiku_draft = Investigation(
        incident_id="INC-EVT-2026-001",
        hypothesis="Confirmed brute-force activity from known malicious IP.",
        attack_chain_summary="External attacker attempted SSH credential stuffing.",
        mitre_techniques=[
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic="Credential Access",
                evidence="Repeated failed logins in raw telemetry.",
            )
        ],
        enriched_iocs=[],
        affected_assets=["srv-backup-01"],
        recommended_severity=Severity.HIGH,
    )
    spy_llm = SpyStructuredLLMClient(responses=[haiku_draft])
    investigator = InvestigatorAgent(
        llm_client=spy_llm,  # type: ignore[arg-type]
        jev_engine=fake_jev,
    )
    incident = Incident(
        incident_id="INC-EVT-2026-001",
        source_event_id="EVT-2026-001",
        title="SSH Brute Force",
        summary="Brute force detected.",
        severity=Severity.HIGH,
        category=IncidentCategory.BRUTE_FORCE,
        confidence=0.90,
        escalate=True,
        initial_indicators=[],
    )

    result, audit = investigator.run(incident, sample_raw_event)

    assert len(spy_llm.calls) == 1
    assert spy_llm.calls[0]["model"] == MODEL_HAIKU
    assert result.hypothesis == haiku_draft.hypothesis
    assert not any(entry.stage == "investigate:sde_cascade_escalated" for entry in audit)


def test_investigator_sde_cascade_escalates_to_sonnet_when_jev_noul_fails(
    sample_raw_event: RawEvent,
) -> None:
    """Si un Noul de verificación cae bajo 0.75, el agente escala automáticamente de Haiku 4.5 a Sonnet 5."""
    fake_jev = FakeJevEngine(
        grounding_checks={
            "grounded_in_iocs": 0.42,  # Falla (< 0.75): alucinación en reputación de IOC
            "mitre_coherent": 0.90,
            "no_speculation": 0.61,   # Falla (< 0.75)
        }
    )
    haiku_hallucinated_draft = Investigation(
        incident_id="INC-EVT-2026-001",
        hypothesis="Unverified APT29 nation-state attribution.",
        attack_chain_summary="Speculative lateral movement.",
        mitre_techniques=[
            MitreTechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic="Credential Access",
                evidence="Failed logins.",
            )
        ],
        enriched_iocs=[],
        affected_assets=["srv-backup-01"],
        recommended_severity=Severity.CRITICAL,
    )
    sonnet_corrected_draft = haiku_hallucinated_draft.model_copy(
        update={
            "hypothesis": "Grounded SSH brute-force attempt verified against local intel.",
            "recommended_severity": Severity.HIGH,
        }
    )
    spy_llm = SpyStructuredLLMClient(
        responses=[haiku_hallucinated_draft, sonnet_corrected_draft]
    )
    investigator = InvestigatorAgent(
        llm_client=spy_llm,  # type: ignore[arg-type]
        jev_engine=fake_jev,
    )
    incident = Incident(
        incident_id="INC-EVT-2026-001",
        source_event_id="EVT-2026-001",
        title="SSH Brute Force",
        summary="Brute force detected.",
        severity=Severity.HIGH,
        category=IncidentCategory.BRUTE_FORCE,
        confidence=0.90,
        escalate=True,
        initial_indicators=[],
    )

    result, audit = investigator.run(incident, sample_raw_event)

    assert len(spy_llm.calls) == 2
    assert spy_llm.calls[0]["model"] == MODEL_HAIKU
    assert spy_llm.calls[1]["model"] == MODEL_SONNET
    assert "grounded_in_iocs: Noul=0.42" in spy_llm.calls[1]["user_prompt"]
    assert result.hypothesis == "Grounded SSH brute-force attempt verified against local intel."
    assert any(entry.stage == "investigate:sde_cascade_escalated" for entry in audit)