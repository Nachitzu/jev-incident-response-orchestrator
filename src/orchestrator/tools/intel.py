"""Offline-first threat intelligence, ATT&CK and playbook lookups.

These are plain functions over the bundled JSON under `data/`, wrapped in the
`ThreatIntelLookup` facade the agents consume. `toolcli.py` exposes the same
functions as `soar-tool` subcommands, and `toolbox.py` wraps them as Anthropic
tool definitions for console/API tool loops.

Offline-first is a design commitment, not a limitation: the demo must be
reproducible on a laptop with no keys. Live lookups (AbuseIPDB) are consulted
only for indicators the local set does not know, and only when
`ABUSEIPDB_API_KEY` is set.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from functools import lru_cache
from pathlib import Path
from typing import Any

from orchestrator.schemas.common import guess_indicator_type
from orchestrator.schemas.investigation import EnrichedIOC
from orchestrator.schemas.raw_event import RawEvent

# What a reputation lookup returns when the indicator is not in local intel.
UNKNOWN_REPUTATION = "unknown"


def data_dir() -> Path:
    """Locate the intel data directory.

    `SOAR_DATA_DIR` overrides everything. Otherwise prefer the copy installed
    next to the package (pip installs force-include `data/` inside
    `orchestrator/`), then the repository checkout for source-tree runs.
    """
    override = os.environ.get("SOAR_DATA_DIR")
    if override:
        return Path(override)
    this = Path(__file__).resolve()
    pkg_root = this.parents[1]        # .../orchestrator
    repo_root = this.parents[3]      # source checkout root
    for candidate in (pkg_root / "data", repo_root / "data"):
        if candidate.exists():
            return candidate
    return repo_root / "data"


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
    as an error: "we have no data" is a legitimate investigative finding, and
    an agent that sees an exception here would be tempted to invent one.
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


# --------------------------------------------------------------------------
# agent-facing facade
# --------------------------------------------------------------------------
def _abuseipdb_live_from_env() -> Callable[[str], dict[str, Any] | None] | None:
    """Build a live AbuseIPDB lookup when ABUSEIPDB_API_KEY is set, else None."""
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return None

    def live(indicator: str) -> dict[str, Any] | None:
        import httpx

        try:
            response = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": indicator, "maxAgeInDays": 90},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json().get("data") or {}
        except Exception:  # noqa: BLE001
            # A live feed that is down must degrade to "unknown", never break triage.
            return None
        score = float(data.get("abuseConfidenceScore") or 0)
        if score >= 75:
            reputation = "malicious"
        elif score >= 25:
            reputation = "suspicious"
        else:
            reputation = "benign"
        return {
            "type": "ip",
            "reputation": reputation,
            "source": "abuseipdb",
            "detail": data,
        }

    return live


class ThreatIntelLookup:
    """Object facade over the offline intel set used by the agents.

    `live` is consulted only for indicators the local set does not know; by
    default it is an AbuseIPDB lookup when ABUSEIPDB_API_KEY is set, and None
    (fully offline) otherwise.
    """

    def __init__(
        self,
        *,
        live: Callable[[str], dict[str, Any] | None] | None = None,
    ) -> None:
        self._live = live if live is not None else _abuseipdb_live_from_env()

    @property
    def mitre_catalog_by_id(self) -> dict[str, dict[str, Any]]:
        return {t["technique_id"]: dict(t) for t in _attack_catalog()}

    def lookup(
        self, indicator: str, type_hint: str | None = None
    ) -> dict[str, Any]:
        return lookup_reputation(indicator, type_hint, live=self._live)

    def get_mitre_candidates_for_category(
        self, category: str, *, limit: int = 8
    ) -> list[dict[str, Any]]:
        """Lexical candidate techniques for an incident category."""
        return rank_techniques({"category": category}, [], limit=limit)

    def enrich_event_indicators(
        self,
        *,
        raw_event: RawEvent,
        initial_indicators: list[str] | None = None,
    ) -> list[EnrichedIOC]:
        """Enrich the incident's seed indicators plus everything the event names.

        Order is preserved and duplicates collapsed: agent-provided indicators
        first (they carry the detector's intent), then the event's own
        observables and endpoints.
        """
        indicators: list[str] = []
        for value in list(initial_indicators or []) + list(raw_event.observables):
            if value and value not in indicators:
                indicators.append(value)
        for value in (raw_event.source_ip, raw_event.destination_ip):
            if value and value not in indicators:
                indicators.append(value)

        enriched: list[EnrichedIOC] = []
        for value in indicators:
            entry = self.lookup(value)
            enriched.append(
                EnrichedIOC(
                    indicator=value,
                    type=guess_indicator_type(value),
                    reputation=entry.get("reputation", UNKNOWN_REPUTATION),
                    source=entry.get("source", "local_intel"),
                    detail=entry.get("detail"),
                )
            )
        return enriched
