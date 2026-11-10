"""Responder: incident plus investigation in, a suggested response plan out.

The plan is advice — this system never executes anything against a host. The
safety rules that matter (a destructive step must carry an approval flag, the
plan-level flag must match its steps) are enforced by `ResponsePlan` itself, so
this module's job is mostly to hand the model the right base playbook and let
the contract referee the result.
"""

from __future__ import annotations

import json
from typing import Any

from src.orchestrator import _llm
from src.orchestrator import _jev
from src.orchestrator.schemas import Incident, Investigation, ResponsePlan
from src.orchestrator.tools import intel
from src.orchestrator.tools.toolbox import RESPONDER_TOOLS, Toolbox

AGENT_NAME = "ResponderAgent"
PROMPT = "responder"


def build_user_content(
    incident: Incident,
    investigation: Investigation,
    *,
    playbook_category: str | None = None,
) -> str:
    category = playbook_category or incident.category
    playbook = intel.get_playbook(category)
    base = (
        json.dumps(playbook, indent=2)
        if playbook is not None
        else (
            f"(no base playbook exists for category {category!r}; "
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


def _check(incident: Incident):
    def guard(plan: ResponsePlan) -> None:
        if plan.incident_id != incident.incident_id:
            raise ValueError(
                f"incident_id must be copied exactly: expected "
                f"{incident.incident_id!r}, got {plan.incident_id!r}"
            )

    return guard


def respond(
    incident: Incident,
    investigation: Investigation,
    *,
    client: Any,
    model: str = _llm.RESPONDER_MODEL,
    toolbox: Toolbox | None = None,
    jev_engine: Any | None = None,
) -> ResponsePlan:
    """Produce a prioritized, human-gated response plan."""
    if investigation.incident_id != incident.incident_id:
        raise ValueError(
            "investigation belongs to a different incident than the one given"
        )
    toolbox = toolbox if toolbox is not None else Toolbox(names=RESPONDER_TOOLS)
    engine = jev_engine or _jev.JevEngine()
    playbook_category = incident.category
    selector = getattr(engine, "select_playbook", None)
    if getattr(engine, "enabled", False) and selector is not None:
        playbook_category = selector(
            incident.model_dump(mode="json"),
            investigation.model_dump(mode="json"),
            {
                category: intel.get_playbook(category)
                for category in intel.playbook_categories()
            },
        )
    plan = _llm.complete_validated(
        ResponsePlan,
        client=client,
        model=model,
        system=_llm.load_prompt(PROMPT),
        user_content=build_user_content(
            incident, investigation, playbook_category=playbook_category
        ),
        toolbox=toolbox,
        extra_check=_check(incident),
    )
    scorer = getattr(engine, "score_response_steps", None)
    if getattr(engine, "enabled", False) and scorer is not None:
        scores = scorer(
            incident.model_dump(mode="json"),
            [step.model_dump(mode="json") for step in plan.steps],
        )
        for step, (hitl_noul, blast_radius_score, _confidence) in zip(
            plan.steps, scores, strict=True
        ):
            step.hitl_noul = hitl_noul
            step.blast_radius_score = blast_radius_score
            if blast_radius_score >= 1.5 or hitl_noul >= 0.50:
                step.requires_approval = True
                step.automatable = False
        plan.requires_human_approval = any(
            step.requires_approval for step in plan.steps
        )
        plan = ResponsePlan.model_validate(plan.model_dump(mode="json"))
    return plan
