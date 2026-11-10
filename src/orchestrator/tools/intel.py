"""Offline-first threat intelligence, ATT&CK and playbook lookups.

These are plain functions over the bundled JSON under `data/`. They are the
single implementation used by both run modes: `toolcli.py` exposes them as
`soar-tool` subcommands for the Claude Code console mode, and `toolbox.py` wraps
them as Anthropic tool definitions for API mode.

Offline-first is a design commitment, not a limitation: the demo must be
reproducible on a laptop with no keys. `lookup_reputation()` accepts an optional
`live` callable so a real API (AbuseIPDB and friends) can be injected later
without any of the callers changing.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

# What a reputation lookup returns when the indicator is not in local intel.
UNKNOWN_REPUTATION = "unknown"


def data_dir() -> Path:
    """Locate the repo's `data/` directory.

    Resolved from this file so the lookups work from any CWD; `SOAR_DATA_DIR`
    overrides it (used by tests and by anyone pointing the demo at their own
    intel set).
    """
    override = os.environ.get("SOAR_DATA_DIR")
    if override:
        return Path(override)
    return Path(__file__).resolve().parents[3] / "data"


def _load(*parts: str) -> Any:
    with (data_dir().joinpath(*parts)).open(encoding="utf-8") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _reputation_db() -> dict[str, dict[str, Any]]:
    return _load("intel", "reputation.json").get("indicators", {})


@lru_cache(maxsize=1)
def _attack_catalog() -> tuple[dict[str, str], ...]:
    return tuple(_load("attack", "enterprise-techniques.json").get("techniques", []))


@lru_cache(maxsize=1)
def _playbook_db() -> dict[str, dict[str, Any]]:
    return _load("playbooks", "playbooks.json").get("playbooks", {})


def clear_caches() -> None:
    """Drop the memoized data sets (tests repoint `SOAR_DATA_DIR` between runs)."""
    _reputation_db.cache_clear()
    _attack_catalog.cache_clear()
    _playbook_db.cache_clear()


# --------------------------------------------------------------------------
# reputation
# --------------------------------------------------------------------------
def lookup_reputation(
    indicator: str,
    type_hint: str | None = None,
    *,
    live: Callable[[str], dict[str, Any] | None] | None = None,
) -> dict[str, Any]:
    """Return what is known about one indicator.

    An indicator missing from local intel is reported as `unknown` rather than
    as an error: "we have no data" is a legitimate investigative finding, and an
    agent that sees an exception here would be tempted to invent one.
    """
    entry = _reputation_db().get(indicator)
    if entry is None and live is not None:
        entry = live(indicator)
    if entry is None:
        return {
            "status": "unknown",
            "indicator": indicator,
            "type": type_hint,
            "reputation": UNKNOWN_REPUTATION,
            "source": "local_intel",
        }
    result = {
        "status": "ok",
        "indicator": indicator,
        "type": entry.get("type"),
        "reputation": entry.get("reputation", UNKNOWN_REPUTATION),
        "source": entry.get("source", "local_intel"),
        "detail": entry.get("detail"),
    }
    if type_hint and entry.get("type") != type_hint:
        # Worth surfacing but not fatal: the value, not the type, keys the set.
        result["type_hint_mismatch"] = type_hint
    return result


# --------------------------------------------------------------------------
# ATT&CK
# --------------------------------------------------------------------------
def verify_technique(technique_id: str) -> dict[str, Any]:
    """Check a technique id against the local catalog.

    This is the anti-hallucination guardrail: the investigator may only emit
    technique ids that come back `ok` here, so a plausible-looking but invented
    T-number never reaches a report.
    """
    match = next(
        (t for t in _attack_catalog() if t["technique_id"] == technique_id), None
    )
    if match is None:
        return {"status": "not_found", "technique_id": technique_id}
    return {"status": "ok", "technique": match}


def search_techniques(query: str) -> dict[str, Any]:
    """Find catalog entries whose id, name or tactic contains `query`."""
    needle = query.lower()
    hits = [
        t
        for t in _attack_catalog()
        if needle in t["technique_id"].lower()
        or needle in t["name"].lower()
        or needle in t["tactic"].lower()
    ]
    return {"status": "ok", "query": query, "matches": hits}


def rank_techniques(
    incident: dict[str, Any],
    enriched_iocs: list[dict[str, Any]],
    *,
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Return a deterministic shortlist from the local ATT&CK catalog.

    This lexical pass is intentionally conservative: it can only return entries
    that exist in the bundled catalog, and gives Jev a small, relevant batch to
    re-rank instead of sending the whole catalog to the investigator.
    """
    context = json.dumps(
        {"incident": incident, "enriched_iocs": enriched_iocs},
        default=str,
    ).lower()
    tokens = set(re.findall(r"[a-z0-9]+", context))
    category = str(incident.get("category", "")).lower().replace("_", " ")
    candidates: list[tuple[int, int, dict[str, str]]] = []
    for index, technique in enumerate(_attack_catalog()):
        words = set(
            re.findall(
                r"[a-z0-9]+",
                f"{technique['name']} {technique['tactic']}",
            )
        )
        score = len(words & tokens)
        if category and category in technique["name"].lower():
            score += 3
        candidates.append((score, -index, technique))
    candidates.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return [technique for _, _, technique in candidates[: max(1, limit)]]


# --------------------------------------------------------------------------
# playbooks
# --------------------------------------------------------------------------
def get_playbook(category: str) -> dict[str, Any] | None:
    """Return the base playbook for an incident category, or None if there is none."""
    return _playbook_db().get(category)


def playbook_categories() -> list[str]:
    return sorted(_playbook_db())
