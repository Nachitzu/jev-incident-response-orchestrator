"""Stage 1 — DetectorAgent (Triage & Classification with Jev System One + Claude Haiku 4.5)."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from orchestrator._llm import MODEL_HAIKU, StructuredLLMClient, wrap_untrusted_event
from orchestrator.schemas.common import (
    AuditEntry,
    IncidentCategory,
    Severity,
    SystemOneTelemetry,
)
from orchestrator.schemas.incident import Incident
from orchestrator.schemas.raw_event import RawEvent

if TYPE_CHECKING:
    from orchestrator._jev import TriageAssessment


class JevTriageProtocol(Protocol):
    """Protocolo inyectable para permitir mocks deterministas en tests offline."""

    @property
    def enabled(self) -> bool: ...

    def evaluate_raw_event(self, raw_event: dict[str, Any]) -> TriageAssessment: ...


PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "detector.md"

_INJECTION_NOUNL_ALERT = 0.50


class DetectorAgent:
    """Ejecuta el triaje inicial combinando TypeSafe Jev (System 1) y Claude Haiku 4.5 (System 2)."""

    def __init__(
        self,
        llm_client: StructuredLLMClient | None = None,
        jev_engine: JevTriageProtocol | None = None,
        model: str = MODEL_HAIKU,
        fp_noul_threshold: float = 0.25,
        contained_noul_threshold: float = 0.80,
        confidence_floor: float = 0.65,
    ) -> None:
        self.llm = llm_client or StructuredLLMClient()
        self.jev = jev_engine
        self.model = model
        self.fp_noul_threshold = fp_noul_threshold
        self.contained_noul_threshold = contained_noul_threshold
        self.confidence_floor = confidence_floor
        self._system_prompt = (
            PROMPT_PATH.read_text(encoding="utf-8")
            if PROMPT_PATH.exists()
            else "You are an expert SOC Tier-1 Triage Analyst."
        )

    def run(self, event: RawEvent) -> tuple[Incident, list[AuditEntry]]:
        """Evalua un RawEvent y devuelve el contrato Incident junto con su traza de auditoria."""
        audit_entries: list[AuditEntry] = []
        raw_payload = event.model_dump(mode="json")

        jev_assessment: TriageAssessment | None = None
        if self.jev is not None and self.jev.enabled:
            jev_assessment = self.jev.evaluate_raw_event(raw_payload)
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="detect:jev_system_one",
                    actor="JevEngine (System One)",
                    action="speculative_fanout_triage",
                    details=(
                        f"is_threat={jev_assessment.is_threat_prob:.2f}, "
                        f"already_contained={jev_assessment.already_contained_prob:.2f}, "
                        f"prompt_injection={jev_assessment.prompt_injection_prob:.2f}, "
                        f"category={jev_assessment.category} (conf={jev_assessment.category_confidence:.2f}, "
                        f"fits={jev_assessment.category_fits_prob:.2f}), "
                        f"severity={jev_assessment.severity_label} "
                        f"(score={jev_assessment.severity_score:.2f}, conf={jev_assessment.severity_confidence:.2f})"
                    ),
                )
            )

            # 1. Cortocircuito System One: Falso Positivo claro ("Screen with a Noul first")
            if (
                not jev_assessment.requires_escalation
                and jev_assessment.is_threat_prob < self.fp_noul_threshold
                and jev_assessment.prompt_injection_prob < _INJECTION_NOUNL_ALERT
            ):
                incident = self._build_short_circuit_fp_incident(event, jev_assessment)
                audit_entries.append(
                    AuditEntry(
                        timestamp=datetime.now(UTC),
                        stage="detect:short_circuit",
                        actor="DetectorAgent",
                        action="dismiss_false_positive_without_llm",
                        details=jev_assessment.drop_reason
                        or "Filtered by Jev Noul threshold.",
                    )
                )
                return incident, audit_entries

            # 1b. jev-only: clasificacion 100% determinista, sin LLM generativo.
            if getattr(self.jev, "mode", "hybrid") == "jev-only":
                incident = self._build_jev_only_incident(event, jev_assessment)
                audit_entries.append(
                    AuditEntry(
                        timestamp=datetime.now(UTC),
                        stage="detect:jev_only",
                        actor="DetectorAgent",
                        action="classify_incident_without_llm",
                        details=f"jev-only mode; {incident.summary}",
                    )
                )
                return incident, audit_entries

        # 2. Construccion del prompt para System 2 (Claude Haiku 4.5) con anclaje Jev
        user_prompt = self._build_user_prompt(event, jev_assessment)
        incident = self.llm.generate_structured(
            model=self.model,
            system_prompt=self._system_prompt,
            user_prompt=user_prompt,
            response_model=Incident,
        )

        # 3. Reconciliacion y Guardrails post-LLM usando las primitivas calibradas de Jev
        if jev_assessment is not None:
            incident = self._reconcile_with_jev(incident, jev_assessment, audit_entries)

        audit_entries.append(
            AuditEntry(
                timestamp=datetime.now(UTC),
                stage="detect:completed",
                actor=f"DetectorAgent ({self.model})",
                action="classify_incident",
                details=(
                    f"incident_id={incident.incident_id}, severity={incident.severity.value}, "
                    f"category={incident.category.value}, escalate={incident.escalate}"
                ),
            )
        )
        return incident, audit_entries

    def _telemetry(self, assessment: TriageAssessment) -> SystemOneTelemetry:
        return SystemOneTelemetry(
            prompt_injection_noul=assessment.prompt_injection_prob,
            is_threat_noul=assessment.is_threat_prob,
            already_contained_noul=assessment.already_contained_prob,
            category_fits_noul=assessment.category_fits_prob,
            category_confidence=assessment.category_confidence,
            category_probabilities=dict(assessment.category_probabilities or {}),
            severity_score=assessment.severity_score,
            severity_confidence=assessment.severity_confidence,
            escalated_by_cascade=assessment.prompt_injection_prob >= _INJECTION_NOUNL_ALERT,
        )

    def _seed_indicators(self, event: RawEvent) -> list[str]:
        indicators: list[str] = []
        for value in list(event.observables) + [
            event.source_ip,
            event.destination_ip,
        ]:
            if value and value not in indicators:
                indicators.append(value)
        return indicators

    def _build_short_circuit_fp_incident(
        self,
        event: RawEvent,
        assessment: TriageAssessment,
    ) -> Incident:
        """Construye un Incident benigno de forma 100% determinista cuando Jev descarta amenaza."""
        mapped_category = self._safe_category(assessment.category)
        return Incident(
            incident_id=f"INC-{event.event_id}",
            source_event_id=event.event_id,
            title=f"[False Positive Filtered by Jev] Benign {event.source} activity on {event.hostname or 'host'}",
            summary=(
                f"System One (Jev) evaluated this event as benign operational telemetry "
                f"(is_threat Noul={assessment.is_threat_prob:.2f} < {self.fp_noul_threshold}). "
                f"Skipped generative LLM escalation."
            ),
            severity=Severity.LOW,
            category=mapped_category,
            confidence=round(1.0 - assessment.is_threat_prob, 4),
            escalate=False,
            false_positive_reason=assessment.drop_reason
            or f"Benign operational activity confirmed by System One (is_threat={assessment.is_threat_prob:.2f}).",
            initial_indicators=self._seed_indicators(event),
            system_one_telemetry=self._telemetry(assessment),
        )

    def _build_jev_only_incident(
        self,
        event: RawEvent,
        assessment: TriageAssessment,
    ) -> Incident:
        """Construye el Incident escalado solo con las primitivas de Jev (modo jev-only)."""
        try:
            severity = Severity(assessment.severity_label.upper())
        except ValueError:
            severity = Severity.LOW
        confidence = max(
            assessment.is_threat_prob,
            assessment.category_confidence,
            assessment.severity_confidence,
        )
        if severity in (Severity.HIGH, Severity.CRITICAL):
            # The schema requires at least even odds for a HIGH escalation.
            confidence = max(confidence, 0.5)
        warning = (
            " Prompt-injection alert: Jev probability "
            f"{assessment.prompt_injection_prob:.2f}; payload instructions were "
            "ignored and could not lower severity."
            if assessment.prompt_injection_prob >= _INJECTION_NOUNL_ALERT
            else ""
        )
        return Incident(
            incident_id=f"INC-{event.event_id}",
            source_event_id=event.event_id,
            title="Incident classified by Jev System One",
            summary=(
                f"Jev classified the event as {assessment.category}/{severity}; "
                f"is_threat={assessment.is_threat_prob:.2f}, "
                f"severity_score={assessment.severity_score:.2f}.{warning}"
            ),
            severity=severity,
            category=self._safe_category(assessment.category),
            confidence=round(confidence, 4),
            escalate=True,
            initial_indicators=self._seed_indicators(event),
            system_one_telemetry=self._telemetry(assessment),
        )

    def _build_user_prompt(
        self,
        event: RawEvent,
        assessment: TriageAssessment | None,
    ) -> str:
        """Envuelve el evento no confiable e inyecta los priors matematicos de Jev."""
        wrapped_event = wrap_untrusted_event(event.model_dump(mode="json"))
        if assessment is None:
            return (
                "Analyze the following raw security event and return a valid Incident JSON.\n\n"
                f"{wrapped_event}"
            )

        jev_context = {
            "is_threat_noul": round(assessment.is_threat_prob, 4),
            "already_contained_noul": round(assessment.already_contained_prob, 4),
            "prompt_injection_noul": round(assessment.prompt_injection_prob, 4),
            "category_choice": assessment.category,
            "category_confidence": round(assessment.category_confidence, 4),
            "category_fits_noul": round(assessment.category_fits_prob, 4),
            "severity_score_0_to_3": round(assessment.severity_score, 4),
            "severity_label": assessment.severity_label,
            "severity_confidence": round(assessment.severity_confidence, 4),
        }
        return (
            "Analyze the following raw security event and return a valid Incident JSON.\n"
            "Use the calibrated TypeSafe System One (Jev) priors below as authoritative "
            "grounding for severity, category, and escalation decisions:\n"
            f"<jev_system_one_priors>\n{json.dumps(jev_context, indent=2)}\n</jev_system_one_priors>\n\n"
            f"{wrapped_event}"
        )

    def _reconcile_with_jev(
        self,
        incident: Incident,
        assessment: TriageAssessment,
        audit_entries: list[AuditEntry],
    ) -> Incident:
        """Aplica reglas deterministas en Python sobre las probabilidades de Jev.

        Las reconstrucciones vuelven por `Incident.model_validate`, nunca por
        `model_copy(update=...)`: los guardrails del contrato (p. ej. HIGH
        exige confidence >= 0.5) tambien aplican a lo que el propio guardrail
        modifica.
        """
        updates: dict[str, Any] = {}

        # Regla A: Si Jev detecta Prompt Injection en el log, forzar escalado y advertir
        if assessment.prompt_injection_prob >= _INJECTION_NOUNL_ALERT:
            updates["escalate"] = True
            updates["false_positive_reason"] = None
            if incident.severity in (Severity.LOW, Severity.MEDIUM):
                updates["severity"] = Severity.HIGH
                updates["confidence"] = max(incident.confidence, 0.5)
            updates["summary"] = (
                f"[ALERT: Potential Prompt Injection detected in raw telemetry "
                f"(Noul={assessment.prompt_injection_prob:.2f})] {incident.summary}"
            )
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="detect:guardrail",
                    actor="JevEngine",
                    action="override_prompt_injection",
                    details=(
                        "Forced escalate=True and minimum severity=HIGH due to "
                        "injection attempt."
                    ),
                )
            )

        # Regla B: Amenaza real pero ya contenida por EDR/Email Gateway (ej. malware-quarantined-01)
        already_contained = assessment.already_contained_prob
        if (
            assessment.is_threat_prob >= self.fp_noul_threshold
            and already_contained >= self.contained_noul_threshold
            and assessment.prompt_injection_prob < _INJECTION_NOUNL_ALERT
        ):
            if incident.severity in (Severity.HIGH, Severity.CRITICAL):
                updates["severity"] = Severity.LOW
            updates["escalate"] = False
            updates["false_positive_reason"] = (
                f"Threat already mitigated/quarantined at ingestion "
                f"(already_contained Noul={already_contained:.2f})."
            )
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="detect:contained_reconciliation",
                    actor="JevEngine",
                    action="downgrade_already_mitigated_event",
                    details=(
                        f"Set escalate=False because "
                        f"already_contained_noul={already_contained:.2f}."
                    ),
                )
            )

        # Regla C: Si el Score de Jev es bimodal (baja confianza), marcar revision humana
        if assessment.severity_confidence < self.confidence_floor and incident.escalate:
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="detect:low_confidence_score",
                    actor="JevEngine",
                    action="flag_bimodal_severity",
                    details=(
                        f"Severity Score confidence ({assessment.severity_confidence:.2f}) < "
                        f"{self.confidence_floor:.2f}; analyst verification required."
                    ),
                )
            )

        if not updates and incident.system_one_telemetry is None:
            incident = incident.model_copy(update={"system_one_telemetry": self._telemetry(assessment)})
        elif updates:
            data = incident.model_dump(mode="json")
            data.update(updates)
            incident = Incident.model_validate(data)
            incident = incident.model_copy(update={"system_one_telemetry": self._telemetry(assessment)})
        return incident

    @staticmethod
    def _safe_category(raw_cat: str) -> IncidentCategory:
        try:
            return IncidentCategory(raw_cat)
        except ValueError:
            return IncidentCategory.OTHER
