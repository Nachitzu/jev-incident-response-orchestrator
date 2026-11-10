"""SOAR Orchestrator: a multi-agent incident-response pipeline.

Three specialized agents — detector, investigator, responder — cooperate under an
orchestrator that owns the incident state machine and an auditable decision log.
Agents never exchange free-form text; every boundary is a Pydantic contract from
`src.orchestrator.schemas`.
"""

__version__ = "0.1.0"
