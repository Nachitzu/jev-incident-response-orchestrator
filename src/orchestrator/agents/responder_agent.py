"""Stage 3 — ResponderAgent (playbook adaptation with Jev blast-radius gating).

The plan is advice — this system never executes anything against a host. The
safety rules that matter (a destructive step must carry an approval flag, the
plan-level flag must match its steps) are enforced by `ResponsePlan` itself;
this agent adds Jev's second opinion on top: every step gets a human-in-the-loop
Noul and a blast-radius Score, and any step either flags as dangerous is forced
to require approval — by re-validating the plan, never by mutating it behind
the contract's back.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from orchestrator._llm import MODEL_SONNET, StructuredLLMClient
from orchestrator.schemas.common import AuditEntry
from orchestrator.schemas.incident import Incident
from orchestrator.schemas.investigation import Investigation
from orchestrator.schemas.response_plan import ResponsePlan
from orchestrator.tools import intel


class JevResponderProtocol(Protocol):
    """Protocolo para seleccion de playbook y scoring HITL/blast-radius."""

    @property
    def enabled(self) -> bool: ...

    def select_playbook(
        self,
        incident_data: dict[str, Any],
        investigation_data: dict[str, Any],
        playbooks: dict[str, dict[str, Any]],
    ) -> str: ...

    def score_response_steps(
        self,
        incident_data: dict[str, Any],
        steps: list[dict[str, Any]],
    ) -> list[tuple[float, float, float]]: ...


PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "responder.md"

_NO_FALLBACK_PROMPT = (
    "You are a SOC Response Planner. Plans are advice; nothing is executed."
)


class ResponderAgent:
    """Produce a prioritized, human-gated response plan."""

    def __init__(
        self,
        llm_client: StructuredLLMClient | None = None,
        jev_engine: JevResponderProtocol | None = None,
        model: str = MODEL_SONNET,
        hitl_blast_radius: float = 1.5,
        hitl_noul_threshold: float = 0.50,
    ) -> None:
        self.llm = llm_client or StructuredLLMClient()
        self.jev = jev_engine
        self.model = model
        self.hitl_blast_radius = hitl_blast_radius
        self.hitl_noul_threshold = hitl_noul_threshold
        self._system_prompt = (
            PROMPT_PATH.read_text(encoding="utf-8")
            if PROMPT_PATH.exists()
            else _NO_FALLBACK_PROMPT
        )

    def run(
        self,
        incident: Incident,
        investigation: Investigation,
    ) -> tuple[ResponsePlan, list[AuditEntry]]:
        if investigation.incident_id != incident.incident_id:
            raise ValueError(
                "investigation belongs to a different incident than the one given"
            )
        audit_entries: list[AuditEntry] = []

        playbook_category = incident.category.value
        if (
            self.jev is not None
            and self.jev.enabled
            and hasattr(self.jev, "select_playbook")
        ):
            playbook_category = self.jev.select_playbook(
                incident.model_dump(mode="json"),
                investigation.model_dump(mode="json"),
                {
                    category: intel.get_playbook(category)
                    for category in intel.playbook_categories()
                },
            )
            audit_entries.append(
                AuditEntry(
                    timestamp=datetime.now(UTC),
                    stage="respond:jev_playbook",
                    actor="JevEngine (System One)",
                    action="select_playbook",
                    details=f"Selected playbook category: {playbook_category}",
                )
            )

        plan = self.llm.generate_structured(
            model=self.model,
            system_prompt=self._system_prompt,
            user_prompt=self._build_user_prompt(
                incident, investigation, playbook_category
            ),
            response_model=ResponsePlan,
            validator=self._validator(incident),
        )
        audit_entries.append(
            AuditEntry(
                timestamp=datetime.now(UTC),
                stage="respond:draft",
                actor=f"ResponderAgent ({self.model})",
                action="draft_plan",
                details=(
                    f"{plan.playbook_name}: {len(plan.steps)} step(s), "
                    f"{sum(1 for s in plan.steps if s.requires_approval)} needing approval"
                ),
            )
        )

        if (
            self.jev is not None
            and self.jev.enabled
            and hasattr(self.jev, "score_response_steps")
        ):
            scores = self.jev.score_response_steps(
                incident.model_dump(mode="json"),
                [step.model_dump(mode="json") for step in plan.steps],
            )
            forced = 0
            updated_steps: list[dict[str, Any]] = []
            for step, (hitl_noul, blast_radius_score, _confidence) in zip(
                plan.steps, scores, strict=True
            ):
                step_data = step.model_dump(mode="json")
                step_data["hitl_noul"] = hitl_noul
                step_data["blast_radius_score"] = blast_radius_score
                if (
                    blast_radius_score >= self.hitl_blast_radius
                    or hitl_noul >= self.hitl_noul_threshold
                ):
                    if not step_data["requires_approval"]:
                        forced += 1
                    step_data["requires_approval"] = True
                    step_data["automatable"] = False
                updated_steps.append(step_data)

            plan_data = plan.model_dump(mode="json")
            plan_data["steps"] = updated_steps
            plan_data["requires_human_approval"] = any(
                step["requires_approval"] for step in updated_steps
            )
            plan = ResponsePlan.model_validate(plan_data)
            if forced:
                audit_entries.append(
                    AuditEntry(
                        timestamp=datetime.now(UTC),
                        stage="respond:jev_hitl_gate",
                        actor="JevEngine (System One)",
                        action="force_human_approval",
                        details=(
                            f"Forced requires_approval on {forced} step(s) by "
                            f"blast-radius >= {self.hitl_blast_radius} or HITL "
                            f"Noul >= {self.hitl_noul_threshold}."
                        ),
                    )
                )

        audit_entries.append(
            AuditEntry(
                timestamp=datetime.now(UTC),
                stage="respond:completed",
                actor=f"ResponderAgent ({self.model})",
                action="final_plan",
                details=(
                    f"{plan.playbook_name}: {len(plan.steps)} step(s), "
                    f"requires_human_approval={plan.requires_human_approval}"
                ),
            )
        )
        return plan, audit_entries

    @staticmethod
    def _validator(incident: Incident):
        def guard(plan: ResponsePlan) -> None:
            if plan.incident_id != incident.incident_id:
                raise ValueError(
                    f"incident_id must be copied exactly: expected "
                    f"{incident.incident_id!r}, got {plan.incident_id!r}"
                )

        return guard

    @staticmethod
    def _build_user_prompt(
        incident: Incident,
        investigation: Investigation,
        playbook_category: str,
    ) -> str:
        playbook = intel.get_playbook(playbook_category)
        base = (
            json.dumps(playbook, indent=2)
            if playbook is not None
            else (
                f"(no base playbook exists for category {playbook_category!r}; "
                "build one from the evidence, following containment -> eradication -> "
                "recovery)"
            )
        )
        return (
            f"<incident>\n{json.dumps(incident.model_dump(mode='json'), indent=2)}\n</incident>\n\n"
            f"<investigation>\n{json.dumps(investigation.model_dump(mode='json'), indent=2)}\n</investigation>\n\n"
            f"<base_playbook>\n{base}\n</base_playbook>\n\n"
            "Adapt the base playbook to this incident and return the ResponsePlan "
            "JSON object."
        )
