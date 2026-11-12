"""Offline threat-intel, ATT&CK, playbook and toolbox behaviour."""

from __future__ import annotations

import json

import pytest

from orchestrator.schemas import RawEvent
from orchestrator.schemas.common import ObservableType
from orchestrator.tools import intel
from orchestrator.tools.toolbox import INVESTIGATOR_TOOLS, RESPONDER_TOOLS, Toolbox


@pytest.fixture(autouse=True)
def _fresh_caches():
    intel.clear_caches()
    yield
    intel.clear_caches()


# --------------------------------------------------------------------------
# data wiring
# --------------------------------------------------------------------------
def test_data_dir_finds_bundled_data():
    data = intel.data_dir()
    assert (data / "intel" / "reputation.json").exists()
    assert (data / "attack" / "enterprise-techniques.json").exists()
    assert (data / "playbooks" / "playbooks.json").exists()


# --------------------------------------------------------------------------
# reputation
# --------------------------------------------------------------------------
def test_reputation_hit():
    result = intel.lookup_reputation("185.220.101.34")
    assert result["status"] == "ok"
    assert result["reputation"] == "malicious"
    assert result["source"] != ""


def test_reputation_miss_is_a_finding_not_an_error():
    result = intel.lookup_reputation("203.0.113.215")
    assert result["status"] == "unknown"
    assert result["reputation"] == "unknown"


def test_live_callback_only_for_local_misses():
    calls: list[str] = []

    def live(indicator: str):
        calls.append(indicator)
        return {"type": "ip", "reputation": "suspicious", "source": "abuseipdb"}

    known = intel.lookup_reputation("185.220.101.34", live=live)
    assert known["status"] == "ok" and calls == []

    found = intel.lookup_reputation("203.0.113.216", live=live)
    assert found["status"] == "ok"
    assert found["source"] == "abuseipdb"
    assert calls == ["203.0.113.216"]


def test_live_miss_still_reports_unknown():
    result = intel.lookup_reputation("203.0.113.217", live=lambda i: None)
    assert result["status"] == "unknown"


def test_type_hint_mismatch_is_surfaced_not_fatal():
    result = intel.lookup_reputation("185.220.101.34", "domain")
    assert result["status"] == "ok"
    assert result["type_hint_mismatch"] == "domain"


# --------------------------------------------------------------------------
# ATT&CK
# --------------------------------------------------------------------------
def test_verify_technique_ok_and_missing():
    ok = intel.verify_technique("T1566")
    assert ok["status"] == "ok"
    assert ok["technique"]["name"]
    assert intel.verify_technique("T9999")["status"] == "not_found"


def test_search_techniques_matches_name_or_tactic():
    hits = intel.search_techniques("credential")
    assert hits["status"] == "ok" and hits["matches"]
    for match in hits["matches"]:
        blob = json.dumps(match).lower()
        assert "credential" in blob


def test_rank_techniques_stays_inside_the_catalog():
    catalog = {t["technique_id"] for t in intel._attack_catalog()}
    ranked = intel.rank_techniques({"category": "brute_force"}, [], limit=6)
    assert ranked and len(ranked) <= 6
    assert {t["technique_id"] for t in ranked} <= catalog


# --------------------------------------------------------------------------
# playbooks
# --------------------------------------------------------------------------
def test_playbook_lookup():
    categories = intel.playbook_categories()
    assert categories
    for category in categories:
        assert intel.get_playbook(category) is not None
    assert intel.get_playbook("cryptojacking") is None


# --------------------------------------------------------------------------
# ThreatIntelLookup facade
# --------------------------------------------------------------------------
def test_facade_wires_live_through(raw_event):
    seen: list[str] = []

    def live(indicator: str):
        seen.append(indicator)

    lookup = intel.ThreatIntelLookup(live=live)
    assert lookup.lookup("185.220.101.34")["status"] == "ok"
    assert seen == []  # local hit never reaches live
    assert lookup.lookup("203.0.113.218")["status"] == "unknown"
    assert seen == ["203.0.113.218"]


def test_facade_catalog_by_id():
    catalog = intel.ThreatIntelLookup().mitre_catalog_by_id
    assert "T1566" in catalog


def test_mitre_candidates_for_category_are_valid_techniques():
    lookup = intel.ThreatIntelLookup()
    candidates = lookup.get_mitre_candidates_for_category("brute_force", limit=5)
    assert candidates
    for candidate in candidates:
        assert intel.verify_technique(candidate["technique_id"])["status"] == "ok"


def test_enrich_event_indicators_orders_and_dedupes(incident, raw_event):
    enriched = intel.ThreatIntelLookup().enrich_event_indicators(
        raw_event=raw_event, initial_indicators=incident.initial_indicators
    )
    indicators = [ioc.indicator for ioc in enriched]
    assert len(indicators) == len(set(indicators))
    assert indicators[0] == "185.220.101.34"  # agent-provided first
    assert set(indicators) == {"185.220.101.34", "10.0.1.12"}
    assert all(ioc.type == ObservableType.IP for ioc in enriched)
    assert enriched[0].reputation == "malicious"
    assert enriched[-1].reputation == "unknown"


def test_enrich_event_indicators_without_initials():
    event = RawEvent(
        event_id="e",
        source="proxy",
        event_type="connect",
        destination_ip="8.8.8.8",
        raw_payload={"bytes": 10},
    )
    enriched = intel.ThreatIntelLookup(live=lambda i: None).enrich_event_indicators(
        raw_event=event
    )
    assert [ioc.indicator for ioc in enriched] == ["8.8.8.8"]


# --------------------------------------------------------------------------
# Toolbox
# --------------------------------------------------------------------------
def test_toolbox_definitions_are_narrowed_per_agent():
    full = Toolbox()
    assert [d["name"] for d in full.definitions] == [
        "lookup_reputation",
        "verify_attack_technique",
        "search_attack_techniques",
        "get_playbook",
    ]
    responder = Toolbox(names=RESPONDER_TOOLS)
    assert [d["name"] for d in responder.definitions] == ["get_playbook"]
    investigator = Toolbox(names=INVESTIGATOR_TOOLS)
    assert "get_playbook" not in [d["name"] for d in investigator.definitions]


def test_toolbox_dispatch_hit_is_json_and_recorded():
    toolbox = Toolbox()
    content, is_error = toolbox.dispatch(
        "verify_attack_technique", {"technique_id": "T1566"}
    )
    assert is_error is False
    assert json.loads(content)["status"] == "ok"
    assert toolbox.calls == [("verify_attack_technique", {"technique_id": "T1566"})]


def test_toolbox_unknown_tool_is_an_error():
    content, is_error = Toolbox().dispatch("drop_table", {})
    assert is_error is True
    assert "unknown tool" in json.loads(content)["error"]


def test_toolbox_narrowed_surface_refuses_other_tools():
    responder = Toolbox(names=RESPONDER_TOOLS)
    _content, is_error = responder.dispatch(
        "verify_attack_technique", {"technique_id": "T1566"}
    )
    assert is_error is True


def test_toolbox_missing_argument_is_an_error():
    content, is_error = Toolbox().dispatch("lookup_reputation", {})
    assert is_error is True
    assert "missing required argument" in json.loads(content)["error"]


def test_toolbox_handler_crash_degrades_to_error():
    import orchestrator.tools.toolbox as toolbox_module

    original_handler = toolbox_module.HANDLERS["lookup_reputation"]

    def explode(args):
        raise RuntimeError("kaboom")

    toolbox_module.HANDLERS["lookup_reputation"] = explode
    try:
        content, is_error = Toolbox().dispatch("lookup_reputation", {"indicator": "x"})
        assert is_error is True
        assert "kaboom" in json.loads(content)["error"]
    finally:
        toolbox_module.HANDLERS["lookup_reputation"] = original_handler
