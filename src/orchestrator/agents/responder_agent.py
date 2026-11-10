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
from src.orchestrator.schemas import Incident, Investigation, ResponsePlan
from src.orchestrator.tools import intel
from src.orchestrator.tools.toolbox import RESPONDER_TOOLS, Toolbox

AGENT_NAME = "ResponderAgent"
PROMPT = "responder"


def build_user_content(incident: Incident, investigation: Investigation) -> str:
    playbook = intel.get_playbook(incident.category)
    base = (
        json.dumps(playbook, indent=2)
        if playbook is not None
        else (
            f"(no base playbook exists for category {incident.category!r}; "
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
) -> ResponsePlan:
    """Produce a prioritized, human-gated response plan."""
    if investigation.incident_id != incident.incident_id:
        raise ValueError(
            "investigation belongs to a different incident than the one given"
        )
    toolbox = toolbox if toolbox is not None else Toolbox(names=RESPONDER_TOOLS)
    return _llm.complete_validated(
        ResponsePlan,
        client=client,
        model=model,
        system=_llm.load_prompt(PROMPT),
        user_content=build_user_content(incident, investigation),
        toolbox=toolbox,
        extra_check=_check(incident),
    )
