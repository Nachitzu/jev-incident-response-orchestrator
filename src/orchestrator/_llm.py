"""Shared Anthropic plumbing for the three agents.

Every agent in this pipeline does the same four things: load a system prompt,
call the model (optionally with tools), pull a JSON object out of the reply, and
validate it against its contract — retrying with the validation error when the
model gets it wrong. Rather than repeat that in `detector_agent.py`,
`investigator_agent.py` and `responder_agent.py`, it lives here once.

Nothing in this module imports a concrete agent, so it stays testable with a fake
client: `complete_validated()` takes the client as an argument and never builds
one itself.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable, Protocol, TypeVar

from pydantic import BaseModel

# Model routing. The detector runs on the cheapest capable model because it sees
# every event; the investigator and responder reason over far fewer, far denser
# inputs and get the stronger one.
DETECTOR_MODEL = "claude-haiku-4-5-20251001"
INVESTIGATOR_MODEL = "claude-sonnet-5"
INVESTIGATOR_FAST_MODEL = "claude-haiku-4-5-20251001"
RESPONDER_MODEL = "claude-sonnet-5"

MAX_TOKENS = 4096
MAX_TOOL_ROUNDS = 6
MAX_VALIDATION_ATTEMPTS = 3

PROMPT_DIR = Path(__file__).resolve().parent / "prompts"

_PROMPT_FENCE = re.compile(r"```text\n(.*?)```", re.DOTALL)

T = TypeVar("T", bound=BaseModel)


class LLMError(RuntimeError):
    """The model could not produce a valid contract within the retry budget."""


class ToolDispatcher(Protocol):
    """The slice of a toolbox the completion loop needs.

    Kept structural so tests can pass a stub without importing the real toolbox.
    """

    @property
    def definitions(self) -> list[dict[str, Any]]: ...

    def dispatch(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]: ...


# --------------------------------------------------------------------------
# prompts
# --------------------------------------------------------------------------
def load_prompt(name: str) -> str:
    """Return the verbatim system prompt for an agent.

    Prompt files are Markdown so a human can read the rationale; only the fenced
    ```text block is sent to the model. Both run modes (API and Claude Code
    console) read the same file, so the two can never drift apart.
    """
    path = PROMPT_DIR / f"{name}.md"
    text = path.read_text(encoding="utf-8")
    match = _PROMPT_FENCE.search(text)
    if match is None:
        raise LLMError(f"{path.name} has no ```text block to use as a system prompt")
    return match.group(1).strip()


def cacheable_system(prompt: str) -> list[dict[str, Any]]:
    """Wrap a system prompt in a cache-eligible block.

    The prompts are long and identical across every run, so marking them
    ephemeral turns most of the per-call system cost into a cache read.
    """
    return [
        {
            "type": "text",
            "text": prompt,
            "cache_control": {"type": "ephemeral"},
        }
    ]


# --------------------------------------------------------------------------
# JSON recovery
# --------------------------------------------------------------------------
def extract_json_object(text: str) -> dict[str, Any]:
    """Pull a JSON object out of a model reply, tolerating the usual noise.

    Three escalating strategies: the reply is already JSON; the JSON sits inside
    a code fence; or it is embedded in prose and has to be found by balancing
    braces. Anything that survives one of them is parsed, so an otherwise good
    answer is never thrown away over a stray "Here is the result:".
    """
    stripped = text.strip()
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    fenced = re.search(r"```(?:json)?\s*\n(.*?)```", stripped, re.DOTALL)
    if fenced:
        try:
            parsed = json.loads(fenced.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

    start = stripped.find("{")
    if start != -1:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(stripped)):
            char = stripped[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(stripped[start : index + 1])
                        if isinstance(parsed, dict):
                            return parsed
                    except json.JSONDecodeError:
                        break

    raise LLMError(f"no JSON object found in model reply: {stripped[:200]!r}")


# --------------------------------------------------------------------------
# completion
# --------------------------------------------------------------------------
def _text_of(blocks: Any) -> str:
    return "\n".join(
        block.text for block in blocks if getattr(block, "type", None) == "text"
    ).strip()


def run_completion(
    *,
    client: Any,
    model: str,
    system: str,
    messages: list[dict[str, Any]],
    toolbox: ToolDispatcher | None = None,
    max_tokens: int = MAX_TOKENS,
) -> str:
    """Run one completion, servicing any tool calls, and return the final text.

    `messages` is mutated in place with the assistant turns and tool results, so
    the caller can keep appending to the same conversation across a retry.
    """
    tools = toolbox.definitions if toolbox is not None else None

    for _ in range(MAX_TOOL_ROUNDS):
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": cacheable_system(system),
            "messages": messages,
        }
        if tools:
            kwargs["tools"] = tools

        response = client.messages.create(**kwargs)
        messages.append({"role": "assistant", "content": response.content})

        tool_uses = [
            block for block in response.content
            if getattr(block, "type", None) == "tool_use"
        ]
        if not tool_uses or toolbox is None:
            return _text_of(response.content)

        results = []
        for use in tool_uses:
            content, is_error = toolbox.dispatch(use.name, dict(use.input))
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": use.id,
                    "content": content,
                    "is_error": is_error,
                }
            )
        messages.append({"role": "user", "content": results})

    raise LLMError(f"tool loop did not converge after {MAX_TOOL_ROUNDS} rounds")


def complete_validated(
    schema: type[T],
    *,
    client: Any,
    model: str,
    system: str,
    user_content: str,
    toolbox: ToolDispatcher | None = None,
    extra_check: Callable[[T], None] | None = None,
    max_attempts: int = MAX_VALIDATION_ATTEMPTS,
) -> T:
    """Call the model until its reply validates against `schema`.

    The contract is the referee: a reply that breaks a business rule (a HIGH
    incident with 0.3 confidence, a destructive step without an approval flag)
    is rejected here and the pydantic error is fed back verbatim, which is a far
    stronger correction signal than restating the rule in the prompt.

    `extra_check` covers the rules a schema cannot see on its own — that an id
    was copied across a stage, that a cited ATT&CK technique actually exists. It
    raises `ValueError` and is treated exactly like a validation failure, so the
    model gets to correct it instead of the run dying.
    """
    messages: list[dict[str, Any]] = [{"role": "user", "content": user_content}]
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        text = run_completion(
            client=client,
            model=model,
            system=system,
            messages=messages,
            toolbox=toolbox,
        )
        try:
            result = schema.model_validate(extract_json_object(text))
            if extra_check is not None:
                extra_check(result)
            return result
        except (ValueError, LLMError) as exc:  # ValidationError is a ValueError
            last_error = exc
            if attempt == max_attempts:
                break
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Your previous reply did not satisfy the {schema.__name__} "
                        f"contract:\n\n{exc}\n\nReturn ONLY a corrected JSON object."
                    ),
                }
            )

    raise LLMError(
        f"{schema.__name__} never validated after {max_attempts} attempts: {last_error}"
    )
