"""The bundled scenarios must stay valid inputs and carry consistent labels.

These are the Phase 0 fixtures every later phase runs against, so a typo that makes
one unparseable — or a label pointing at a missing file — should fail here, not
halfway through an agent run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.orchestrator.schemas import RawEvent
from src.orchestrator.schemas.common import IncidentCategory

SCENARIO_DIR = Path(__file__).resolve().parents[1] / "data" / "scenarios"
LABELS_PATH = SCENARIO_DIR / "labels.json"

VALID_CATEGORIES = set(IncidentCategory.__args__)


def _scenario_files() -> list[Path]:
    return sorted(p for p in SCENARIO_DIR.glob("*.json") if p.name != "labels.json")


def test_scenarios_exist() -> None:
    files = _scenario_files()
    assert len(files) >= 10, "the brief calls for 10-15 scenarios"


@pytest.mark.parametrize("path", _scenario_files(), ids=lambda p: p.stem)
def test_scenario_events_are_valid_raw_events(path: Path) -> None:
    events = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(events, list) and events, f"{path.name}: expected a non-empty list"
    for raw in events:
        RawEvent.model_validate(raw)  # raises on any invalid event


def test_labels_are_consistent() -> None:
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    file_ids = {p.stem for p in _scenario_files()}
    assert set(labels) == file_ids, "every scenario needs exactly one label entry"

    for sid, label in labels.items():
        assert isinstance(label["escalate"], bool)
        if label["escalate"]:
            assert label["category"] in VALID_CATEGORIES, f"{sid}: bad category"
        else:
            assert label["category"] is None, f"{sid}: a dropped scenario has no category"


def test_scenario_mix_has_both_outcomes() -> None:
    labels = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    outcomes = {label["escalate"] for label in labels.values()}
    assert outcomes == {True, False}, "the set must exercise both escalate and drop"
