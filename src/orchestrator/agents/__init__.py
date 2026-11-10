"""The three specialized agents.

Each module exposes one pure function — `detect`, `investigate`, `respond` —
that takes its input contract plus an injected Anthropic client and returns the
next contract. No agent knows about the orchestrator, and none of them builds a
client, so every one of them is testable offline.
"""

from src.orchestrator.agents.detector_agent import detect
from src.orchestrator.agents.investigator_agent import investigate
from src.orchestrator.agents.responder_agent import respond

__all__ = ["detect", "investigate", "respond"]
