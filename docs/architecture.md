# Architecture

This document describes how a raw security event becomes an auditable incident
case, and why each boundary in the system exists. It is the public, repo-level
companion to the internal design notes.

## The pipeline

```
  data/scenarios/*.json  (list of RawEvent)
        │
        ▼  RawEvent[]
  ┌───────────────────────────────────────────────────────────────┐
  │ src/orchestrator/agents/detector_agent.py                      │
  │   RawEvent[] → DetectionResult (escalate + Incident | drop)    │
  │   no tools, Haiku: highest volume, cheapest stage              │
  └───────────────────────────┬───────────────────────────────────┘
                              │ Incident
                              ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ src/orchestrator/agents/investigator_agent.py                  │
  │   Incident → Investigation                                     │
  │   tools (tools/toolbox.py → tools/intel.py):                   │
  │     lookup_reputation        (local intel, live API optional)  │
  │     verify_attack_technique  (local ATT&CK catalog)            │
  │     search_attack_techniques (local ATT&CK catalog)            │
  └───────────────────────────┬───────────────────────────────────┘
                              │ Investigation
                              ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ src/orchestrator/agents/responder_agent.py                     │
  │   Incident + Investigation → ResponsePlan                     │
  │   adapts a base playbook from data/playbooks/playbooks.json   │
  └───────────────────────────┬───────────────────────────────────┘
                              │ ResponsePlan
                              ▼
  ┌───────────────────────────────────────────────────────────────┐
  │ src/orchestrator/orchestrator.py                               │
  │   state machine + audit log → CaseReport                      │
  └───────────────────────────┬───────────────────────────────────┘
                              ▼
                    reports/*.md  +  reports/*.json
```

## The state machine

```
              detector.escalate = False
  DETECTED ───────────────────────────────► CLOSED_FALSE_POSITIVE
     │ escalate = True
     ▼
  INVESTIGATING
     │
     ▼
  RESPONSE_SUGGESTED
     │  requires_human_approval?
     ├── yes ──► ESCALATED_TO_HUMAN
     └── no  ──► CLOSED_RESOLVED_SUGGESTED
```

Invalid transitions raise `OrchestratorError`. Every transition and every agent
decision appends an `AuditEntry` (timestamp, stage, agent, model, decision,
inputs digest) so a `CaseReport` can be replayed end to end.

## Components

| Path | Responsibility |
|------|----------------|
| `src/orchestrator/schemas/` | The five inter-agent contracts + shared types. The safety boundary: nothing downstream trusts a model's text until it validates here. |
| `src/orchestrator/agents/` | One module per agent. Each is a pure `run(input, *, client, model, toolbox, ...) -> output` with a validate-and-retry loop; the Anthropic client is injectable so tests never reach the network. |
| `src/orchestrator/prompts/` | System prompts as Markdown, sent verbatim from a fenced ` ```text ` block; the rest of each file is rationale for humans. |
| `src/orchestrator/tools/` | `intel.py` holds the offline reputation, ATT&CK and playbook lookups; `toolbox.py` publishes them as an Anthropic tool surface (`definitions` + `dispatch() -> (content, is_error)`) and narrows that surface per agent. Both run modes call the same `intel.py`. |
| `src/orchestrator/_llm.py` | Shared Anthropic helpers (`cacheable_system`, JSON extraction, thinking/effort, the tool-use loop) so the three agents don't duplicate them. |
| `src/orchestrator/orchestrator.py` | The incident state machine and `run_case()`. |
| `src/orchestrator/reporting/` | Renders a `CaseReport` to Markdown and JSON. |
| `src/orchestrator/cli.py` | `argparse` entry point (`soar-orchestrator run/scenarios/playbooks`). The only place an Anthropic client is ever constructed. |
| `src/orchestrator/toolcli.py` | `soar-tool`: the deterministic half of the pipeline, exposed for the API-free Claude Code console mode. |

## Design commitments

1. **Strict contracts, not free text.** Every agent boundary is a Pydantic model;
   business rules are `@model_validator`s, so a violation is a hard failure.
2. **Offline-first threat intel.** The demo runs with no third-party keys against
   local reputation data and a local ATT&CK catalog. APIs are an injectable
   enhancement, never a dependency of the happy path.
3. **Human-in-the-loop is enforced.** A destructive playbook step cannot omit its
   approval flag; the schema rejects it.
4. **Auditability.** The `AuditLog` lets an analyst reconstruct *why* every
   conclusion was reached — the same interpretability goal as the triage agent.
   A dropped case is recorded too: "we decided this was noise, and here is the
   reason" is an outcome, not silence.
5. **One prompt, two run modes.** `src/orchestrator/prompts/*.md` are the single
   source of truth. API mode loads the fenced `text` block through
   `_llm.load_prompt()`; the Claude Code console mode loads the same block via its
   slash-commands. Neither mode can drift from the other.
