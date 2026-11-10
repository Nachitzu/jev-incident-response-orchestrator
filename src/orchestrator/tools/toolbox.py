"""The tool surface the investigator and responder are given in API mode.

`Toolbox` is deliberately thin: it publishes Anthropic tool `definitions` and a
`dispatch()` that returns `(content, is_error)`. Both halves are data, so a test
can substitute a fake toolbox without touching the agents, and an agent never
learns where a lookup actually came from.

Every handler degrades gracefully. A lookup that finds nothing returns a normal
result saying so; only a genuinely malformed call is flagged `is_error`, because
an error block is a signal to the model to change what it is doing, and "no data"
is not that.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from src.orchestrator.tools import intel

ToolHandler = Callable[[dict[str, Any]], dict[str, Any]]

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "lookup_reputation",
        "description": (
            "Look up the reputation of one observable (IP, domain, URL, hash, email) "
            "in local threat intelligence. Returns reputation "
            "malicious|suspicious|benign|unknown. An unknown indicator is a valid "
            "finding, not a failure."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "The observable value"},
                "type": {
                    "type": "string",
                    "description": "Optional type hint: ip, domain, url, sha256, md5, email",
                },
            },
            "required": ["indicator"],
        },
    },
    {
        "name": "verify_attack_technique",
        "description": (
            "Verify a MITRE ATT&CK technique id against the local catalog. You MUST "
            "call this before citing any technique; only ids that return status 'ok' "
            "may appear in your output."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "technique_id": {
                    "type": "string",
                    "description": "Technique id, e.g. T1566 or T1110.001",
                }
            },
            "required": ["technique_id"],
        },
    },
    {
        "name": "search_attack_techniques",
        "description": (
            "Search the ATT&CK catalog by id fragment, technique name or tactic. Use "
            "it to find the right technique id before verifying it."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "get_playbook",
        "description": (
            "Return the base NIST 800-61 playbook for an incident category "
            "(phishing, brute_force, malware, exfiltration, lateral_movement, recon)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"category": {"type": "string"}},
            "required": ["category"],
        },
    },
]


def _handle_reputation(args: dict[str, Any]) -> dict[str, Any]:
    return intel.lookup_reputation(args["indicator"], args.get("type"))


def _handle_verify(args: dict[str, Any]) -> dict[str, Any]:
    return intel.verify_technique(args["technique_id"])


def _handle_search(args: dict[str, Any]) -> dict[str, Any]:
    return intel.search_techniques(args["query"])


def _handle_playbook(args: dict[str, Any]) -> dict[str, Any]:
    category = args["category"]
    playbook = intel.get_playbook(category)
    if playbook is None:
        return {
            "status": "not_found",
            "category": category,
            "available": intel.playbook_categories(),
        }
    return {"status": "ok", "playbook": playbook}


HANDLERS: dict[str, ToolHandler] = {
    "lookup_reputation": _handle_reputation,
    "verify_attack_technique": _handle_verify,
    "search_attack_techniques": _handle_search,
    "get_playbook": _handle_playbook,
}

INVESTIGATOR_TOOLS = (
    "lookup_reputation",
    "verify_attack_technique",
    "search_attack_techniques",
)
RESPONDER_TOOLS = ("get_playbook",)


@dataclass
class Toolbox:
    """Offline tools exposed to an agent.

    `names` narrows the surface per agent — the responder has no business
    verifying ATT&CK ids, and a smaller tool list is a smaller thing to misuse.
    `calls` records what was actually used, which is what the audit log reports.
    """

    names: tuple[str, ...] = tuple(HANDLERS)
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    @property
    def definitions(self) -> list[dict[str, Any]]:
        return [d for d in TOOL_DEFINITIONS if d["name"] in self.names]

    def dispatch(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Run one tool call. Returns `(json_content, is_error)`."""
        self.calls.append((name, arguments))
        handler = HANDLERS.get(name)
        if handler is None or name not in self.names:
            return json.dumps({"error": f"unknown tool {name!r}"}), True
        try:
            result = handler(arguments)
        except KeyError as exc:
            return json.dumps({"error": f"missing required argument {exc}"}), True
        except Exception as exc:  # pragma: no cover - defensive
            return json.dumps({"error": f"{type(exc).__name__}: {exc}"}), True
        return json.dumps(result, default=str), False
