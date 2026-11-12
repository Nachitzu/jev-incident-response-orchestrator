"""The three specialized agents.

Each module exposes one agent class that takes its input contracts plus an
injected structured-LLM client (and, optionally, a Jev engine) and returns the
next contract plus its audit trail. No agent knows about the orchestrator, and
none of them builds a client, so every one of them is testable offline.
"""

from orchestrator.agents.detector_agent import DetectorAgent
from orchestrator.agents.investigator_agent import InvestigatorAgent
from orchestrator.agents.responder_agent import ResponderAgent

__all__ = ["DetectorAgent", "InvestigatorAgent", "ResponderAgent"]
