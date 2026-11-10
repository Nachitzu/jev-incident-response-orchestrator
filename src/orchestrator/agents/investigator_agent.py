"""Investigator: an incident in, an evidence-backed investigation out.

This is the stage that can hallucinate most expensively — an invented ATT&CK
technique looks exactly like a real one in a report — so verification is not left
to the prompt. Every `technique_id` the model returns is checked against the
local catalog inside the retry loop, and an unverified id sends the answer back
with the reason attached.
"""

from __future__ import annotations

import json
from typing import Any

from src.orchestrator import _llm
from src.orchestrator.schemas import Incident, Investigation
from src.orchestrator.tools import intel
from src.orchestrator.tools.toolbox import INVESTIGATOR_TOOLS, Toolbox

AGENT_NAME = "InvestigatorAgent"
PROMPT = "investigator"


def build_user_content(incident: Incident) -> str:
    payload = json.dumps(incident.model_dump(mode="json"), indent=2)
    return (
        f"<incident>\n{payload}\n</incident>\n\n"
        "Enrich every observable, verify each ATT&CK technique before citing it, "
        "and return the Investigation JSON object."
    )


def _check(incident: Incident):
    """Build the post-validation guard for this incident.

    Runs inside the retry loop, so a violation is a correction the model gets to
    act on rather than a crash.
    """

    def guard(investigation: Investigation) -> None:
        if investigation.incident_id != incident.incident_id:
            raise ValueError(
                f"incident_id must be copied exactly: expected "
                f"{incident.incident_id!r}, got {investigation.incident_id!r}"
            )
        unverified = [
            t.technique_id
            for t in investigation.mitre_techniques
            if intel.verify_technique(t.technique_id)["status"] != "ok"
        ]
        if unverified:
            raise ValueError(
                "these technique ids are not in the ATT&CK catalog and must be "
                f"removed or replaced: {', '.join(unverified)}"
            )

    return guard


def investigate(
    incident: Incident,
    *,
    client: Any,
    model: str = _llm.INVESTIGATOR_MODEL,
    toolbox: Toolbox | None = None,
) -> Investigation:
    """Turn an escalated incident into a defensible investigation."""
    toolbox = toolbox if toolbox is not None else Toolbox(names=INVESTIGATOR_TOOLS)
    return _llm.complete_validated(
        Investigation,
        client=client,
        model=model,
        system=_llm.load_prompt(PROMPT),
        user_content=build_user_content(incident),
        toolbox=toolbox,
        extra_check=_check(incident),
    )
