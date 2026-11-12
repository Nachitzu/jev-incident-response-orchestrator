"""Stage 2 — InvestigatorAgent with SDE Cascade (Haiku 4.5 -> Jev Noul Audit -> Sonnet 5)."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from orchestrator._llm import (
    MODEL_HAIKU,
    MODEL_SONNET,
    StructuredLLMClient,
    wrap_untrusted_event,
)
from orchestrator.schemas.common import AuditEntry
from orchestrator.schemas.incident import Incident
from orchestrator.schemas.investigation import (
    EnrichedIOC,
    Investigation,
)
from orchestrator.schemas.raw_event import RawEvent
from orchestrator.tools.intel import ThreatIntelLookup


class JevInvestigatorProtocol(Protocol):
    """Protocolo para verificacion de alucinaciones y re-ranking MITRE con System One."""

    @property
    def enabled(self) -> bool: ...

    def verify_investigation(
        self,
        incident_data: dict[str, Any],
        enriched_iocs: list[dict[str, Any]],
        investigation_draft: dict[str, Any],
    ) -> dict[str, float]: ...

    def rank_mitre_candidates(
        self,
        incident_data: dict[str, Any],
        candidates: list[dict[str, Any]],
        top_k: int = 5,
    ) -> list[str]: ...


PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "investigator.md"

_NO_FALLBACK_PROMPT = (
    "You are a Senior SOC Tier-2 Threat Hunter and Forensic Investigator."
)


class InvestigatorAgent:
    """Enriquece IOCs, mapea MITRE ATT&CK y ejecuta la cascada Haiku -> Jev -> Sonnet."""

    def __init__(
        self,
        llm_client: StructuredLLMClient | None = None,
        intel_tool: ThreatIntelLookup | None = None,
        jev_engine: JevInvestigatorProtocol | None = None,
        fast_model: str = MODEL_HAIKU,
        reasoning_model: str = MODEL_SONNET,
        grounding_threshold: float = 0.75,
    ) -> None:
        self.llm = llm_client or StructuredLLMClient()
        self.intel = intel_tool or ThreatIntelLookup()
        self.jev = jev_engine
        self.fast_model = fast_model
        self.reasoning_model = reasoning_model
        self.grounding_threshold = grounding_threshold
        self._system_prompt = (
            PROMPT_PATH.read_text(encoding="utf-8")
            if PROMPT_PATH.exists()
            else _NO_FALLBACK_PROMPT
        )

    def run(
        self,
        incident: Incident,
        raw_event: RawEvent,
    ) -> tuple[Investigation, list[AuditEntry]]:
        """Ejecuta el enriquecimiento determinista y la cascada SDE supervisada por Jev."""
        audit_entries: list[AuditEntry] = []

        # 1. Enriquecimiento determinista de IOCs ANTES de llamar a Jev o al LLM
        enriched_iocs: list[EnrichedIOC] = self.intel.enrich_event_indicators(
            raw_event=raw_event,
            initial_indicators=incident.initial_indicators,
        )
        enriched_dicts = [ioc.model_dump(mode="json") for ioc in enriched_iocs]
        audit_entries.append(
            AuditEntry(
                timestamp=datetime.now(UTC),
                stage="investigate:intel_enrichment",
                actor="ThreatIntelLookup",
                action="enrich_iocs",
                details=(
                    f"Enriched {len(enriched_iocs)} indicators against local threat intel."
                ),
            )
        )

        # 2. Shortlist de tecnicas MITRE ATT&CK candidatas (opcionalmente re-rankeadas por Jev)
        candidate_techniques = self.intel.get_mitre_candidates_for_category(
            incident.category.value
        )
        if (
            self.jev is not None
            and self.jev.enabled
            and hasattr(self.jev, "rank_mitre_candidates")
            and candidate_techniques
        ):
            ranked_ids = self.jev.rank_mitre_candidates(
                incident_data=incident.model_dump(mode="json"),
                candidates=candidate_techniques,
                top_k=6,
            )
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="investigate:jev_mitre_rerank",
                    actor="JevEngine (System One)",
                    action="rerank_attack_techniques",
                    details=f"Top MITRE candidates selected by Jev: {', '.join(ranked_ids)}",
                )
            )
        else:
            ranked_ids = [t["technique_id"] for t in candidate_techniques[:8]]

        # 3. Paso 1 del SDE Cascade: Extraccion rapida con modelo economico (Haiku 4.5)
        base_prompt = self._build_investigation_prompt(
            incident=incident,
            raw_event=raw_event,
            enriched_iocs=enriched_dicts,
            allowed_mitre_ids=ranked_ids,
        )
        draft = self.llm.generate_structured(
            model=self.fast_model,
            system_prompt=self._system_prompt,
            user_prompt=base_prompt,
            response_model=Investigation,
            validator=self._validate_mitre_catalog,
        )
        audit_entries.append(
            AuditEntry(
                timestamp=datetime.now(UTC),
                stage="investigate:sde_cascade_fast",
                actor=f"InvestigatorAgent ({self.fast_model})",
                action="draft_investigation",
                details=(
                    f"Generated initial investigation with {len(draft.mitre_techniques)} "
                    f"ATT&CK techniques."
                ),
            )
        )

        # 4. Paso 2 del SDE Cascade: Auditoria de fidelidad con 3 Nouls en Jev
        if self.jev is not None and self.jev.enabled:
            checks = self.jev.verify_investigation(
                incident_data=incident.model_dump(mode="json"),
                enriched_iocs=enriched_dicts,
                investigation_draft=draft.model_dump(mode="json"),
            )
            failed_checks = {
                name: score
                for name, score in checks.items()
                if score < self.grounding_threshold
            }
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="investigate:jev_grounding_check",
                    actor="JevEngine (System One)",
                    action="verify_llm_output",
                    details=(
                        "Grounding Nouls: "
                        + ", ".join(f"{k}={v:.2f}" for k, v in checks.items())
                    ),
                )
            )

            # 5. Paso 3 del SDE Cascade: Escalar a Claude Sonnet 5 SOLO si un check falla
            if failed_checks:
                escalation_feedback = (
                    "Jev System One verification flagged low grounding confidence on the "
                    "fast draft:\n"
                    + "\n".join(
                        f"- {name}: Noul={score:.2f} (minimum required: "
                        f"{self.grounding_threshold:.2f})"
                        for name, score in failed_checks.items()
                    )
                    + "\nStrictly ground every IOC claim in <enriched_threat_intel> and "
                    "only select MITRE ATT&CK techniques directly evidenced by the "
                    "telemetry."
                )
                draft = self.llm.generate_structured(
                    model=self.reasoning_model,
                    system_prompt=self._system_prompt,
                    user_prompt=(
                        f"{base_prompt}\n\n<jev_audit_feedback>\n{escalation_feedback}"
                        "\n</jev_audit_feedback>"
                    ),
                    response_model=Investigation,
                    validator=self._validate_mitre_catalog,
                )
                audit_entries.append(
                    AuditEntry(
                        timestamp=datetime.now(UTC),
                        stage="investigate:sde_cascade_escalated",
                        actor=f"InvestigatorAgent ({self.reasoning_model})",
                        action="escalate_to_reasoning_model",
                        details=(
                            f"Escalated to {self.reasoning_model} due to failed checks: "
                            f"{list(failed_checks.keys())}"
                        ),
                    )
                )

        # Garantizar que los IOCs enriquecidos deterministas esten presentes en el contrato final
        if not draft.enriched_iocs and enriched_iocs:
            data = draft.model_dump(mode="json")
            data["enriched_iocs"] = [ioc.model_dump(mode="json") for ioc in enriched_iocs]
            draft = Investigation.model_validate(data)

        return draft, audit_entries

    def _validate_mitre_catalog(self, investigation: Investigation) -> None:
        """Valida que cada technique_id exista en data/attack/enterprise-techniques.json."""
        valid_catalog = self.intel.mitre_catalog_by_id
        if not valid_catalog:
            return
        invalid_ids = [
            tech.technique_id
            for tech in investigation.mitre_techniques
            if tech.technique_id not in valid_catalog
        ]
        if invalid_ids:
            suggestions = sorted(valid_catalog)[:5]
            raise ValueError(
                f"MITRE ATT&CK technique IDs not found in local catalog: {invalid_ids}. "
                f"Use search_attack_techniques to find valid ids (examples: "
                f"{', '.join(suggestions)})."
            )

    def _build_investigation_prompt(
        self,
        incident: Incident,
        raw_event: RawEvent,
        enriched_iocs: list[dict[str, Any]],
        allowed_mitre_ids: list[str],
    ) -> str:
        catalog_subset = [
            self.intel.mitre_catalog_by_id[tid]
            for tid in allowed_mitre_ids
            if tid in self.intel.mitre_catalog_by_id
        ]
        return (
            "Investigate the escalated security incident below using the pre-enriched "
            "Threat Intel and the allowed MITRE ATT&CK techniques.\n\n"
            f"<escalated_incident>\n{json.dumps(incident.model_dump(mode='json'), indent=2)}\n</escalated_incident>\n\n"
            f"<enriched_threat_intel>\n{json.dumps(enriched_iocs, indent=2)}\n</enriched_threat_intel>\n\n"
            f"<allowed_mitre_attack_catalog>\n{json.dumps(catalog_subset, indent=2)}\n</allowed_mitre_attack_catalog>\n\n"
            f"{wrap_untrusted_event(raw_event.model_dump(mode='json'))}"
        )
