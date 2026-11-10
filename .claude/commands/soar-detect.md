---
description: Detector stage only — decide escalate/drop for a scenario, no API key.
argument-hint: <path/to/scenario.json>
allowed-tools: Bash(soar-tool:*), Read, Write
---

Console mode (no Anthropic API): you are the DETECTOR.

1. Read the scenario JSON at **$ARGUMENTS** (a `RawEvent[]`).
2. Read `src/orchestrator/prompts/detector.md` and follow that verbatim prompt exactly.
3. Write your `DetectionResult` JSON to `scratch/detection.json`.
4. Validate: `soar-tool validate --schema detection-result --in scratch/detection.json`.
   On a validation error, fix the JSON and re-run (max 2 retries); a validation error
   means your reasoning broke a rule, not that the schema is wrong.
5. Report the outcome: escalate (with the incident's title/category/severity/confidence)
   or drop (with the drop_reason).
