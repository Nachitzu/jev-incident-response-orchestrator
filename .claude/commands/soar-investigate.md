---
description: Investigator stage only — enrich an incident into an Investigation, no API key.
argument-hint: <path/to/incident.json>
allowed-tools: Bash(soar-tool:*), Read, Write
---

Console mode (no Anthropic API): you are the INVESTIGATOR.

1. Read the `Incident` JSON at **$ARGUMENTS**.
2. Read `src/orchestrator/prompts/investigator.md` and follow that verbatim prompt.
3. Enrich each observable with `soar-tool intel "<value>" --type <type>`.
4. Verify every ATT&CK id with `soar-tool attack verify T####` before including it
   (use `soar-tool attack search <term>` to find the right id); drop anything that
   returns `not_found`.
5. Write your `Investigation` JSON to `scratch/investigation.json` and validate:
   `soar-tool validate --schema investigation --in scratch/investigation.json`
   (fix and retry on error, max 2 retries).
6. Summarize the hypothesis, confidence, techniques, and recommended severity.
