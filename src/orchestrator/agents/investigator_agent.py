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

from src.orchestrator import _jev
from src.orchestrator import _llm
from src.orchestrator.schemas import Incident, Investigation
from src.orchestrator.tools import intel
from src.orchestrator.tools.toolbox import INVESTIGATOR_TOOLS, Toolbox

AGENT_NAME = "InvestigatorAgent"
PROMPT = "investigator"
JEV_VERIFY_THRESHOLD = 0.75


def build_user_content(
    incident: Incident,
    *,
    enriched_iocs: list[dict[str, Any]] | None = None,
    technique_shortlist: list[dict[str, Any]] | None = None,
    retry_rules: str | None = None,
) -> str:
    payload = json.dumps(incident.model_dump(mode="json"), indent=2)
    content = (
        f"<incident>\n{payload}\n</incident>\n\n"
        "Enrich every observable, verify each ATT&CK technique before citing it, "
        "and return the Investigation JSON object."
    )
    if enriched_iocs is not None:
        content += f"\n\n<enriched_iocs>\n{json.dumps(enriched_iocs, indent=2)}</enriched_iocs>"
    if technique_shortlist is not None:
        content += (
            "\n\n<mitre_shortlist>\n"
            f"{json.dumps(technique_shortlist, indent=2)}\n"
            "</mitre_shortlist>\nUse only technique ids from this shortlist."
        )
    if retry_rules:
        content += (
            "\n\n<JEV_RETRY_RULES>\n"
            f"{retry_rules}\n"
            "</JEV_RETRY_RULES>\nCorrect every listed rule failure."
        )
    return content


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
    jev_engine: Any | None = None,
    fast_model: str = _llm.INVESTIGATOR_FAST_MODEL,
) -> Investigation:
    """Turn an escalated incident into a defensible investigation."""
    toolbox = toolbox if toolbox is not None else Toolbox(names=INVESTIGATOR_TOOLS)
    engine = jev_engine or _jev.JevEngine()
    incident_data = incident.model_dump(mode="json")
    enriched_iocs = [
        intel.lookup_reputation(observable.value, observable.type)
        for observable in incident.observables
    ]
    candidates = intel.rank_techniques(incident_data, enriched_iocs)
    if getattr(engine, "enabled", False):
        ranker = getattr(
            engine,
            "rerank_attack_techniques",
            getattr(engine, "rerank_techniques", None),
        )
        if ranker is not None:
            candidates = ranker(incident_data, enriched_iocs, candidates)

    user_content = build_user_content(
        incident,
        enriched_iocs=enriched_iocs,
        technique_shortlist=candidates,
    )
    try:
        investigation = _llm.complete_validated(
            Investigation,
            client=client,
            model=fast_model if getattr(engine, "enabled", False) else model,
            system=_llm.load_prompt(PROMPT),
            user_content=user_content,
            toolbox=toolbox,
            extra_check=_check(incident),
        )
    except _llm.LLMError as exc:
        if not getattr(engine, "enabled", False):
            raise
        retry_rules = f"- first_pass_validation: {exc}"
        return _llm.complete_validated(
            Investigation,
            client=client,
            model=model,
            system=_llm.load_prompt(PROMPT),
            user_content=build_user_content(
                incident,
                enriched_iocs=enriched_iocs,
                technique_shortlist=candidates,
                retry_rules=retry_rules,
            ),
            toolbox=toolbox,
            extra_check=_check(incident),
        )

    verify = getattr(engine, "verify_investigation", None)
    if not getattr(engine, "enabled", False) or verify is None:
        return investigation
    scores = verify(incident_data, enriched_iocs, investigation.model_dump(mode="json"))
    failed = [
        f"- {name}: {score:.2f} (< {JEV_VERIFY_THRESHOLD:.2f})"
        for name, score in scores.items()
        if score < JEV_VERIFY_THRESHOLD
    ]
    if not failed:
        return investigation
    return _llm.complete_validated(
        Investigation,
        client=client,
        model=model,
        system=_llm.load_prompt(PROMPT),
        user_content=build_user_content(
            incident,
            enriched_iocs=enriched_iocs,
            technique_shortlist=candidates,
            retry_rules="\n".join(failed),
        ),
        toolbox=toolbox,
        extra_check=_check(incident),
    )
