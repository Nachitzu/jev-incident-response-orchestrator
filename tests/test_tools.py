"""Offline intel lookups and the Anthropic tool surface built on top of them."""

from __future__ import annotations

import json

from src.orchestrator.tools import intel
from src.orchestrator.tools.toolbox import (
    INVESTIGATOR_TOOLS,
    RESPONDER_TOOLS,
    Toolbox,
)


def test_a_known_indicator_comes_back_with_its_reputation() -> None:
    result = intel.lookup_reputation("185.220.101.34", "ip")
    assert result["status"] == "ok"
    assert result["reputation"] == "malicious"


def test_an_unknown_indicator_is_a_finding_not_an_error() -> None:
    result = intel.lookup_reputation("198.51.100.7", "ip")
    assert result["status"] == "unknown"
    assert result["reputation"] == "unknown"


def test_a_real_technique_verifies_and_an_invented_one_does_not() -> None:
    assert intel.verify_technique("T1110.001")["status"] == "ok"
    assert intel.verify_technique("T9999")["status"] == "not_found"


def test_search_finds_techniques_by_name() -> None:
    matches = intel.search_techniques("phishing")["matches"]
    assert any(m["technique_id"] == "T1566" for m in matches)


def test_every_playbook_category_has_steps() -> None:
    for category in intel.playbook_categories():
        playbook = intel.get_playbook(category)
        assert playbook is not None and playbook["steps"]


def test_the_toolbox_only_publishes_the_tools_it_was_given() -> None:
    names = {d["name"] for d in Toolbox(names=RESPONDER_TOOLS).definitions}
    assert names == {"get_playbook"}
    assert "verify_attack_technique" in {
        d["name"] for d in Toolbox(names=INVESTIGATOR_TOOLS).definitions
    }


def test_dispatch_returns_json_and_no_error_for_a_valid_call() -> None:
    box = Toolbox(names=INVESTIGATOR_TOOLS)
    content, is_error = box.dispatch("verify_attack_technique", {"technique_id": "T1566"})
    assert is_error is False
    assert json.loads(content)["status"] == "ok"
    assert box.calls == [("verify_attack_technique", {"technique_id": "T1566"})]


def test_a_tool_outside_the_published_set_is_an_error() -> None:
    content, is_error = Toolbox(names=RESPONDER_TOOLS).dispatch(
        "verify_attack_technique", {"technique_id": "T1566"}
    )
    assert is_error is True
    assert "unknown tool" in json.loads(content)["error"]


def test_a_missing_argument_is_reported_as_an_error_not_a_crash() -> None:
    content, is_error = Toolbox().dispatch("lookup_reputation", {})
    assert is_error is True
    assert "missing required argument" in json.loads(content)["error"]


def test_an_unknown_playbook_category_lists_the_alternatives() -> None:
    content, is_error = Toolbox(names=RESPONDER_TOOLS).dispatch(
        "get_playbook", {"category": "nonexistent"}
    )
    assert is_error is False
    payload = json.loads(content)
    assert payload["status"] == "not_found"
    assert "phishing" in payload["available"]
