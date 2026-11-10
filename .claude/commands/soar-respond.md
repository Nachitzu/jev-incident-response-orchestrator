---
description: Responder stage only — turn an investigation into a suggested ResponsePlan, no API key.
argument-hint: <incident.json> <investigation.json>
allowed-tools: Bash(soar-tool:*), Read, Write
---

Console mode (no Anthropic API): you are the RESPONDER.

1. Read the `Incident` and `Investigation` JSON paths in **$ARGUMENTS**.
2. Pull the base playbook: `soar-tool playbook <incident.category>`.
3. Read `src/orchestrator/prompts/responder.md` and follow that verbatim prompt,
   adapting the playbook to the incident's evidence.
4. Write your `ResponsePlan` JSON to `scratch/response_plan.json` and validate:
   `soar-tool validate --schema response-plan --in scratch/response_plan.json`
   (fix and retry on error, max 2 retries).
5. Remember: destructive steps must set requires_approval=true; automatable steps must
   not; and requires_human_approval must equal any(step.requires_approval).
6. Summarize the plan and whether it needs human approval.
