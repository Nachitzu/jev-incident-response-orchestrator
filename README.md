<h1 align="center">AI Incident Response Orchestrator</h1>

<p align="center"><strong>🚧 Work in progress</strong></p>

<p align="center">
  <em>A SOAR-style multi-agent pipeline that takes a raw security event through
  the incident lifecycle: <b>detect → investigate → respond</b>, with strict
  contracts and human-in-the-loop controls by design.</em>
</p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white">
  <img alt="Pydantic" src="https://img.shields.io/badge/contracts-pydantic%20v2-E92063">
  <img alt="Tests" src="https://img.shields.io/badge/tests-offline%20pytest-0A9EDC">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

<p align="center">English · <a href="README.es.md">Español</a></p>

---

## Overview

A Tier 1 triage agent classifies an alert. A SOC needs more: correlate events
into an incident, investigate it against threat intelligence and MITRE ATT&CK,
and propose a response playbook while escalating potentially harmful actions to
a human.

This project models that lifecycle with three specialized agents coordinated by
an orchestrator that owns the state machine and produces an auditable decision
log. It is the evolution of the
[SOC Triage Agent](https://github.com/Nachitzu/ai-soc-triage-agent): one agent
became a three-stage pipeline.

> **Design principle:** agents never exchange free-form text. Each boundary
> (`RawEvent`, `Incident`, `Investigation`, `ResponsePlan`, `CaseReport`) is a
> validated Pydantic contract. Safety rules are enforced by the schema, not by
> convention.

**Current scope:** the system suggests a playbook and generates a report. It
never executes actions against a host. Architecture and interfaces may change as
the project moves toward v1.

## Highlights

- Separate detection, investigation, and response stages.
- Strict Pydantic v2 contracts between all stages.
- Offline-first threat intelligence with local reputation and MITRE ATT&CK data.
- NIST SP 800-61-aligned response playbooks.
- Human approval required for destructive or high-impact actions.
- Auditable Markdown and JSON case reports.
- Two run modes: Anthropic API or Claude Code console without an API key.
- Offline tests with mocked LLM clients.

## Architecture

```text
  Raw events (data/scenarios/*.json)
        │  RawEvent[]
        ▼
  ┌──────────────┐   drops obvious false positives
  │ DetectorAgent │──────────────────────────────► closed_false_positive
  └──────┬───────┘   Incident
         ▼
  ┌──────────────────┐◄──► Offline-first ThreatIntel
  │ InvestigatorAgent │      local reputation + ATT&CK catalog
  └──────┬───────────┘   Investigation
         ▼
  ┌──────────────┐◄──► JSON playbook library
  │ ResponderAgent│   ResponsePlan + human approval flags
  └──────┬───────┘
         ▼
  ┌───────────────────────────────────────────────┐
  │ Orchestrator: state machine + audit log       │
  │ detected → investigating → response_suggested │
  │          → closed / escalated_to_human         │
  └──────┬────────────────────────────────────────┘
         ▼
  CaseReport (Markdown + JSON)
```

See [`docs/architecture.md`](docs/architecture.md) for the component, state,
and design details.

## Requirements

- Python 3.11 or newer.
- [`uv`](https://docs.astral.sh/uv/) for dependency management and commands.
- `ANTHROPIC_API_KEY` for API mode.
- `TYPESAFE_API_KEY` is optional; Jev can be disabled through configuration.

The bundled threat intelligence works without third-party keys. The optional
`ABUSEIPDB_API_KEY` enables live reputation lookups only.

## Installation

```bash
uv sync --extra dev
```

To configure local variables, copy [`.env.example`](.env.example) to `.env` and
load its values in your shell. The project does not automatically load `.env`.

## Quick start

### Pipeline commands

```bash
# List bundled scenarios
uv run soar-orchestrator scenarios

# List available playbooks
uv run soar-orchestrator playbooks

# Run a scenario and write reports/<incident_id>.md and .json
uv run soar-orchestrator run data/scenarios/phishing-01.json
```

API mode requires `ANTHROPIC_API_KEY`. Override models per stage with
`--detector-model`, `--investigator-model`, and `--responder-model`, or globally
with `SOAR_MODEL`. Use `--no-report` to avoid writing files and `--out reports/`
to change the output directory.

Example summary:

```text
case phishing-01: escalated_to_human
  incident   : Credential-harvesting phishing against a finance user
  category   : phishing / HIGH (confidence 0.86)
  ATT&CK     : T1566.002, T1204.001
  kill chain : delivery
  plan       : 5 step(s), 3 needing human approval
  report     : reports/phishing-01.md  |  reports/phishing-01.json
```

### Claude Code console mode, no API key

Inside a [Claude Code](https://claude.com/claude-code) session in this
repository, the live session performs the reasoning while Python handles only
deterministic plumbing: validation, offline threat intelligence, ATT&CK
verification, playbook selection, and report rendering.

```text
/soar-run data/scenarios/phishing-01.json
```

Individual stages are also available:

```text
/soar-detect data/scenarios/phishing-01.json
/soar-investigate path/to/incident.json
/soar-respond path/to/incident.json path/to/investigation.json
```

Commands live in `.claude/commands/` and use the same prompts in
[`src/orchestrator/prompts/`](src/orchestrator/prompts/). The deterministic
tool can also be called directly:

```bash
uv run soar-tool intel 45.133.1.77 --type ip
uv run soar-tool attack verify T1566
uv run soar-tool attack search phishing
uv run soar-tool playbook phishing
uv run soar-tool validate --schema incident --in incident.json
uv run soar-tool report --case case.json --out reports/
```

`soar-tool` needs no API key and emits JSON on stdout.

## Contracts and states

| Schema | Produced by | Meaning |
|---|---|---|
| `RawEvent` | Ingestion | Raw event from a SIEM, EDR, firewall, or email source |
| `DetectionResult` | DetectorAgent | Escalation decision and resulting `Incident` |
| `Incident` | DetectorAgent | Categorized incident or recorded dismissal |
| `Investigation` | InvestigatorAgent | Enriched IOCs, hypothesis, and verified ATT&CK techniques |
| `ResponsePlan` | ResponderAgent | Prioritized steps with approval flags |
| `CaseReport` | Orchestrator | Complete case and audit log in JSON and Markdown |

The normal flow is:

```text
DETECTED → INVESTIGATING → RESPONSE_SUGGESTED
                         ├→ CLOSED_RESOLVED_SUGGESTED
                         └→ ESCALATED_TO_HUMAN
```

False positives end in `CLOSED_FALSE_POSITIVE`. Invalid transitions fail
explicitly.

## Safety guardrails

| Guardrail | Implementation | Prevents |
|---|---|---|
| Validation and retry | `_llm.complete_validated()` | Invalid responses continuing downstream |
| ATT&CK verification | `investigator_agent.py` | Invented techniques reaching a report |
| Human-in-the-loop | `PlaybookStep` and `ResponsePlan` validators | Destructive steps without approval |
| Identity tracing | Each agent's `extra_check` | Mixing results from different incidents |
| Anti-injection framing | `<events>` and `<incident>` blocks | Treating log data as instructions |
| Offline-first intel | `tools/intel.py` | Depending on an external API for the happy path |

The design also uses Jev patterns for early false-positive screening, calibrated
grounding checks, and blast-radius scoring. Relevant settings include
`SOAR_JEV_MODE`, `SOAR_FP_NOUL_THRESHOLD`, and `SOAR_HITL_CONFIDENCE_MIN`; see
[`.env.example`](.env.example).

## Project structure

```text
src/orchestrator/
├── agents/       # Detector, Investigator, and Responder
├── prompts/      # Prompts shared by both modes
├── schemas/      # Pydantic contracts
├── tools/        # Threat intel, ATT&CK, and playbooks
├── reporting/    # Markdown/JSON rendering
├── cli.py        # soar-orchestrator
├── toolcli.py    # soar-tool
└── orchestrator.py
data/             # Scenarios, local intel, and playbooks
docs/             # Architecture documentation
tests/            # Offline unit and integration tests
```

## Current status

The main flow, contracts, CLI, local playbooks, console mode, and offline test
suite are implemented. The repository is still under active development:
operational integrations, persistence, and controlled execution of real actions
remain future work.

## Development and tests

```bash
uv sync --extra dev
uv run pytest -q
```

The suite is designed not to touch the network or consume APIs. LLM clients are
injected and mocked in tests.

## Limitations and roadmap

The following are not part of the project yet:

- Real containment, eradication, or recovery actions against hosts.
- Direct integrations with commercial SIEM/EDR platforms.
- Persistent case storage or cross-case correlation.
- Web UI.
- Live threat intelligence as the default path.

These capabilities are deferred because they significantly increase the blast
radius and require additional operational controls.

## Author and license

**Nachitzu** — blue team and AI-agent architecture. See also the
[SOC Triage Agent](https://github.com/Nachitzu/ai-soc-triage-agent).

MIT — see [`LICENSE`](LICENSE).
