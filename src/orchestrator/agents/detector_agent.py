"""Detector: raw events in, an escalation decision out.

This is the cheapest and highest-volume stage, so it runs on Haiku and gets no
tools — correlating a handful of events into "incident or noise" needs judgement,
not lookups. Its output is a `DetectionResult`, which by construction is either
an `Incident` or a stated `drop_reason`; there is no third, silent option.
"""

from __future__ import annotations

import json
from typing import Any

from src.orchestrator import _llm
from src.orchestrator.schemas import DetectionResult, RawEvent

AGENT_NAME = "DetectorAgent"
PROMPT = "detector"


def build_user_content(events: list[RawEvent]) -> str:
    """Render the events as the data block the prompt expects.

    The `<events>` wrapper is not decoration: the system prompt tells the model
    that everything inside it is data, which is what keeps a log line reading
    "ignore previous instructions" from being one.
    """
    payload = json.dumps([e.model_dump(mode="json") for e in events], indent=2)
    return (
        f"<events>\n{payload}\n</events>\n\n"
        "Decide escalate or drop and return the DetectionResult JSON object."
    )


def detect(
    events: list[RawEvent],
    *,
    client: Any,
    model: str = _llm.DETECTOR_MODEL,
) -> DetectionResult:
    """Correlate one scenario's events into an escalation decision."""
    if not events:
        raise ValueError("detect() needs at least one event")
    return _llm.complete_validated(
        DetectionResult,
        client=client,
        model=model,
        system=_llm.load_prompt(PROMPT),
        user_content=build_user_content(events),
    )
