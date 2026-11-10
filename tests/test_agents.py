"""The three agents, driven by scripted model replies. Nothing reaches the network."""

from __future__ import annotations

import json

import pytest

from src.orchestrator import _llm
from src.orchestrator.agents import detect, investigate, respond
from src.orchestrator.schemas import Incident, Investigation, RawEvent
from tests.conftest import FakeClient, FakeToolbox, text_block, tool_use_block

ESCALATION = {
    "escalate": True,
    "incident": {
        "incident_id": "inc-0001",
        "created_at": "2026-07-08T03:13:00Z",
        "triggering_events": ["evt-0001"],
        "title": "Probable SSH brute-force compromise of a domain controller",
        "category": "brute_force",
        "severity": "HIGH",
        "detection_confidence": 0.82,
        "rationale": "47 failed logins then a success against dc01",
        "observables": [{"type": "ip", "value": "185.220.101.34"}],
        "status": "detected",
    },
    "drop_reason": None,
}

DROP = {
    "escalate": False,
    "incident": None,
    "drop_reason": "Scheduled backup job from an authorized internal host.",
}

INVESTIGATION = {
    "incident_id": "inc-0001",
    "investigated_at": "2026-07-08T03:20:00Z",
    "mitre_techniques": [
        {
            "technique_id": "T1110.001",
            "name": "Password Guessing",
            "tactic": "Credential Access",
        }
    ],
    "enriched_observables": [
        {
            "observable": {"type": "ip", "value": "185.220.101.34"},
            "reputation": "malicious",
            "source": "local_intel",
        }
    ],
    "hypothesis": "External actor brute-forced SSH and obtained an admin session.",
    "confidence": 0.78,
    "kill_chain_stage": "exploitation",
    "evidence": ["47 failed logins then success", "source ip is a known tor exit"],
    "recommended_severity": "CRITICAL",
}

PLAN = {
    "incident_id": "inc-0001",
    "planned_at": "2026-07-08T03:25:00Z",
    "playbook_name": "Brute-force response (NIST 800-61)",
    "summary": "Contain dc01, rotate the admin credential, then restore access.",
    "steps": [
        {
            "order": 1,
            "phase": "containment",
            "action": "Open a Tier 2 ticket and notify the on-call analyst",
            "requires_approval": False,
            "automatable": True,
            "justification": "Non-destructive coordination",
        },
        {
            "order": 2,
            "phase": "containment",
            "action": "Isolate host dc01 from the network",
            "requires_approval": True,
            "automatable": False,
            "justification": "Isolating a domain controller is disruptive",
        },
    ],
    "requires_human_approval": True,
    "residual_risk": "Lateral movement may predate containment.",
}


# --------------------------------------------------------------------------
# detector
# --------------------------------------------------------------------------
def test_the_detector_escalates_and_keeps_the_incident(raw_event: RawEvent) -> None:
    client = FakeClient([json.dumps(ESCALATION)])
    result = detect([raw_event], client=client)
    assert result.escalate is True
    assert result.incident is not None
    assert result.incident.category == "brute_force"


def test_the_detector_wraps_events_as_data_not_instructions(raw_event: RawEvent) -> None:
    client = FakeClient([json.dumps(DROP)])
    detect([raw_event], client=client)
    sent = client.calls[0]["messages"][0]["content"]
    assert "<events>" in sent and "</events>" in sent


def test_the_detector_runs_on_the_cheap_model_by_default(raw_event: RawEvent) -> None:
    client = FakeClient([json.dumps(DROP)])
    detect([raw_event], client=client)
    assert client.calls[0]["model"] == _llm.DETECTOR_MODEL


def test_a_drop_always_carries_a_reason(raw_event: RawEvent) -> None:
    client = FakeClient([json.dumps(DROP)])
    result = detect([raw_event], client=client)
    assert result.escalate is False
    assert result.drop_reason


def test_the_detector_refuses_an_empty_batch() -> None:
    with pytest.raises(ValueError):
        detect([], client=FakeClient([]))


# --------------------------------------------------------------------------
# investigator
# --------------------------------------------------------------------------
def test_the_investigator_returns_a_verified_investigation(incident: Incident) -> None:
    client = FakeClient([json.dumps(INVESTIGATION)])
    result = investigate(incident, client=client, toolbox=FakeToolbox())
    assert result.incident_id == incident.incident_id
    assert result.mitre_techniques[0].technique_id == "T1110.001"


def test_an_unverifiable_attack_technique_is_sent_back(incident: Incident) -> None:
    hallucinated = {
        **INVESTIGATION,
        "mitre_techniques": [
            {"technique_id": "T9999", "name": "Invented", "tactic": "Nonsense"}
        ],
    }
    client = FakeClient([json.dumps(hallucinated), json.dumps(INVESTIGATION)])
    result = investigate(incident, client=client, toolbox=FakeToolbox())
    assert [t.technique_id for t in result.mitre_techniques] == ["T1110.001"]
    correction = " ".join(
        m["content"]
        for m in client.calls[1]["messages"]
        if isinstance(m["content"], str)
    )
    assert "T9999" in correction and "not in the ATT&CK catalog" in correction


def test_an_investigation_for_the_wrong_incident_is_rejected(incident: Incident) -> None:
    wrong = {**INVESTIGATION, "incident_id": "inc-9999"}
    client = FakeClient([json.dumps(wrong)] * 3)
    with pytest.raises(_llm.LLMError):
        investigate(incident, client=client, toolbox=FakeToolbox())


def test_the_investigator_can_use_its_tools(incident: Incident) -> None:
    toolbox = FakeToolbox({"lookup_reputation": {"reputation": "malicious"}})
    client = FakeClient(
        [
            [tool_use_block("lookup_reputation", {"indicator": "185.220.101.34"})],
            [text_block(json.dumps(INVESTIGATION))],
        ]
    )
    investigate(incident, client=client, toolbox=toolbox)
    assert toolbox.calls[0][0] == "lookup_reputation"


# --------------------------------------------------------------------------
# responder
# --------------------------------------------------------------------------
def test_the_responder_produces_a_human_gated_plan(
    incident: Incident, investigation: Investigation
) -> None:
    client = FakeClient([json.dumps(PLAN)])
    plan = respond(incident, investigation, client=client, toolbox=FakeToolbox())
    assert plan.requires_human_approval is True
    assert any(step.requires_approval for step in plan.steps)


def test_the_responder_is_handed_the_base_playbook(
    incident: Incident, investigation: Investigation
) -> None:
    client = FakeClient([json.dumps(PLAN)])
    respond(incident, investigation, client=client, toolbox=FakeToolbox())
    sent = client.calls[0]["messages"][0]["content"]
    assert "<base_playbook>" in sent
    assert "Brute-force" in sent or "brute_force" in sent


def test_a_plan_that_hides_a_destructive_step_never_validates(
    incident: Incident, investigation: Investigation
) -> None:
    unsafe = {
        **PLAN,
        "steps": [
            {
                "order": 1,
                "phase": "containment",
                "action": "Isolate host dc01 from the network",
                "requires_approval": False,
                "automatable": True,
                "justification": "Fast containment",
            }
        ],
        "requires_human_approval": False,
    }
    client = FakeClient([json.dumps(unsafe)] * 3)
    with pytest.raises(_llm.LLMError):
        respond(incident, investigation, client=client, toolbox=FakeToolbox())


def test_mismatched_inputs_are_caught_before_any_api_call(incident: Incident) -> None:
    foreign = Investigation.model_validate({**INVESTIGATION, "incident_id": "inc-9999"})
    client = FakeClient([])
    with pytest.raises(ValueError):
        respond(incident, foreign, client=client, toolbox=FakeToolbox())
    assert client.calls == []
