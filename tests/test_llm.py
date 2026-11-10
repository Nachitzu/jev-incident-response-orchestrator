"""The shared Anthropic plumbing: prompts, JSON recovery, tools, retries."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel, Field

from src.orchestrator import _llm
from tests.conftest import FakeClient, FakeToolbox, text_block, tool_use_block


class Tiny(BaseModel):
    value: int = Field(ge=10)


def _sent_text(client: FakeClient, call_index: int, needle: str) -> bool:
    """Was `needle` sent as user text in the given request?

    The conversation list is mutated in place across turns, so a test has to look
    at the whole transcript rather than at whichever message happens to be last.
    """
    return any(
        isinstance(message["content"], str) and needle in message["content"]
        for message in client.calls[call_index]["messages"]
    )


# --------------------------------------------------------------------------
# prompts
# --------------------------------------------------------------------------
@pytest.mark.parametrize("name", ["detector", "investigator", "responder"])
def test_every_agent_prompt_has_a_verbatim_block(name: str) -> None:
    prompt = _llm.load_prompt(name)
    assert prompt.startswith("You are the")
    assert "```" not in prompt, "only the fenced content is sent, never the fence"


def test_load_prompt_rejects_a_file_without_a_text_block(tmp_path, monkeypatch) -> None:
    (tmp_path / "broken.md").write_text("# no fence here", encoding="utf-8")
    monkeypatch.setattr(_llm, "PROMPT_DIR", tmp_path)
    with pytest.raises(_llm.LLMError):
        _llm.load_prompt("broken")


def test_cacheable_system_marks_the_prompt_ephemeral() -> None:
    blocks = _llm.cacheable_system("system text")
    assert blocks[0]["cache_control"] == {"type": "ephemeral"}


# --------------------------------------------------------------------------
# JSON recovery
# --------------------------------------------------------------------------
def test_extract_json_accepts_a_bare_object() -> None:
    assert _llm.extract_json_object('{"a": 1}') == {"a": 1}


def test_extract_json_accepts_a_fenced_object() -> None:
    assert _llm.extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}


def test_extract_json_recovers_an_object_buried_in_prose() -> None:
    reply = 'Here is the result:\n{"a": {"b": "}"}}\nHope that helps!'
    assert _llm.extract_json_object(reply) == {"a": {"b": "}"}}


def test_extract_json_raises_when_there_is_no_object() -> None:
    with pytest.raises(_llm.LLMError):
        _llm.extract_json_object("no json at all")


# --------------------------------------------------------------------------
# completion + tools
# --------------------------------------------------------------------------
def test_run_completion_services_a_tool_call_then_returns_the_text() -> None:
    toolbox = FakeToolbox({"lookup_reputation": {"reputation": "malicious"}})
    client = FakeClient(
        [
            [tool_use_block("lookup_reputation", {"indicator": "185.220.101.34"})],
            [text_block('{"value": 42}')],
        ]
    )
    messages: list[dict] = [{"role": "user", "content": "go"}]
    out = _llm.run_completion(
        client=client,
        model="m",
        system="s",
        messages=messages,
        toolbox=toolbox,
    )
    assert out == '{"value": 42}'
    assert toolbox.calls == [("lookup_reputation", {"indicator": "185.220.101.34"})]
    tool_results = messages[2]["content"]
    assert tool_results[0]["type"] == "tool_result"
    assert tool_results[0]["is_error"] is False


def test_run_completion_gives_up_on_a_tool_loop_that_never_converges() -> None:
    toolbox = FakeToolbox({"lookup_reputation": {"reputation": "unknown"}})
    client = FakeClient(
        [[tool_use_block("lookup_reputation", {"indicator": "x"})]] * 20
    )
    with pytest.raises(_llm.LLMError, match="did not converge"):
        _llm.run_completion(
            client=client,
            model="m",
            system="s",
            messages=[{"role": "user", "content": "go"}],
            toolbox=toolbox,
        )


# --------------------------------------------------------------------------
# validation retry
# --------------------------------------------------------------------------
def test_a_contract_violation_is_fed_back_and_corrected() -> None:
    client = FakeClient(['{"value": 3}', '{"value": 30}'])
    result = _llm.complete_validated(
        Tiny, client=client, model="m", system="s", user_content="go"
    )
    assert result.value == 30
    assert _sent_text(client, 1, "did not satisfy the Tiny contract")


def test_giving_up_after_the_attempt_budget_raises() -> None:
    client = FakeClient(['{"value": 1}'] * 3)
    with pytest.raises(_llm.LLMError, match="never validated"):
        _llm.complete_validated(
            Tiny, client=client, model="m", system="s", user_content="go"
        )


def test_extra_check_failures_are_retried_like_validation_errors() -> None:
    def guard(obj: Tiny) -> None:
        if obj.value != 99:
            raise ValueError("value must be exactly 99")

    client = FakeClient(['{"value": 50}', '{"value": 99}'])
    result = _llm.complete_validated(
        Tiny,
        client=client,
        model="m",
        system="s",
        user_content="go",
        extra_check=guard,
    )
    assert result.value == 99
    assert _sent_text(client, 1, "value must be exactly 99")
