---
description: Run the full SOAR pipeline (detect → investigate → respond → report) on a scenario, with no API key — you are the model.
argument-hint: <path/to/scenario.json>
allowed-tools: Bash(soar-tool:*), Bash(python -m src.orchestrator.toolcli:*), Read, Write
---

You are running the **AI Incident Response Orchestrator in console mode**: there is no
Anthropic API call in this flow — *you*, the live Claude Code session, are the three
agents. Python only does the deterministic plumbing via `soar-tool` (validation,
offline threat-intel, ATT&CK verification, playbook lookup, report rendering).

Scenario file: **$ARGUMENTS**

Run the pipeline end to end. At every stage, the agent instructions are the **verbatim
prompt** in the matching file under `src/orchestrator/prompts/` — read it and follow it
exactly; it is the same prompt the API-mode agent uses.

## 1. Detect
1. Read the scenario JSON at `$ARGUMENTS` (a `RawEvent[]`).
2. Read `src/orchestrator/prompts/detector.md` and act as the DETECTOR on those events.
3. Write your `DetectionResult` JSON to `scratch/detection.json`, then validate it:
   `soar-tool validate --schema detection-result --in scratch/detection.json`
4. If validation fails, read the error, fix the JSON, and re-validate (max 2 retries).
5. If `escalate` is false → skip to step 4 (Report) with `final_state =
   closed_false_positive`, no investigation, no plan.

## 2. Investigate  (only if escalated)
1. Read `src/orchestrator/prompts/investigator.md` and act as the INVESTIGATOR on the
   incident from step 1.
2. Enrich each observable: `soar-tool intel "<value>" --type <type>`.
3. Verify **every** ATT&CK id before you use it: `soar-tool attack verify T####`
   (drop any that return `not_found`; search with `soar-tool attack search <term>`).
4. Write `Investigation` JSON to `scratch/investigation.json` and validate:
   `soar-tool validate --schema investigation --in scratch/investigation.json`
   (retry on failure, same as above).

## 3. Respond  (only if escalated)
1. Pull the base playbook: `soar-tool playbook <incident.category>`.
2. Read `src/orchestrator/prompts/responder.md` and act as the RESPONDER, adapting the
   playbook to the evidence.
3. Write `ResponsePlan` JSON to `scratch/response_plan.json` and validate:
   `soar-tool validate --schema response-plan --in scratch/response_plan.json`.

## 4. Report
1. Assemble a `CaseReport` JSON in `scratch/case.json` bundling the incident,
   investigation (or null), response plan (or null), an `audit_log` (one `AuditEntry`
   per stage — set `model` to the model you are running as), the right `final_state`
   (`closed_false_positive` | `closed_resolved_suggested` | `escalated_to_human`;
   escalate to human iff `requires_human_approval` is true), and `generated_at`.
2. Render it: `soar-tool report --case scratch/case.json --out reports/`
3. Tell the user the two output paths and a two-line summary of the outcome.

Never mark a destructive step auto-runnable, and never claim a technique you did not
verify. The schema will reject both — treat a validation error as a signal to fix your
reasoning, not to force the JSON.
