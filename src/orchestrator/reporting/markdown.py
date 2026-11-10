"""Render a `CaseReport` as an analyst-readable Markdown brief.

Both run modes end here: `soar-orchestrator run` calls `write_report()` directly,
and the console mode reaches the same function through `soar-tool report`. The
audit log is rendered last and in full — the point of the whole pipeline is that
someone can read *why* each conclusion was reached, not just what it was.
"""

from __future__ import annotations

from pathlib import Path

from src.orchestrator.schemas import CaseReport


def render_markdown(report: CaseReport) -> str:
    inc = report.incident
    lines: list[str] = [
        f"# Case report — {report.incident_id}",
        "",
        f"**Final state:** `{report.final_state}`  ",
        f"**Generated:** {report.generated_at.isoformat()}",
        "",
        "## Incident",
        f"- **Title:** {inc.title}",
        f"- **Category:** {inc.category}",
        f"- **Severity:** {inc.severity}",
        f"- **Detection confidence:** {inc.detection_confidence:.2f}",
        f"- **Rationale:** {inc.rationale}",
    ]
    if inc.observables:
        lines.append("- **Observables:**")
        lines += [f"  - `{o.type}` {o.value}" for o in inc.observables]

    if report.investigation is not None:
        inv = report.investigation
        lines += [
            "",
            "## Investigation",
            f"- **Hypothesis:** {inv.hypothesis}",
            f"- **Confidence:** {inv.confidence:.2f}",
            f"- **Kill-chain stage:** {inv.kill_chain_stage}",
            f"- **Recommended severity:** {inv.recommended_severity}",
        ]
        if inv.mitre_techniques:
            lines.append("- **ATT&CK techniques:**")
            lines += [
                f"  - {t.technique_id} {t.name} ({t.tactic})"
                for t in inv.mitre_techniques
            ]
        if inv.enriched_observables:
            lines.append("- **Enriched observables:**")
            lines += [
                f"  - `{e.observable.type}` {e.observable.value} → "
                f"**{e.reputation}** ({e.source})"
                for e in inv.enriched_observables
            ]
        if inv.evidence:
            lines.append("- **Evidence:**")
            lines += [f"  - {item}" for item in inv.evidence]

    if report.response_plan is not None:
        plan = report.response_plan
        flag = (
            "human approval required"
            if plan.requires_human_approval
            else "auto-closeable"
        )
        lines += [
            "",
            "## Response plan",
            f"- **Playbook:** {plan.playbook_name}",
            f"- **Summary:** {plan.summary}",
            f"- **Approval:** {flag}",
            f"- **Residual risk:** {plan.residual_risk}",
            "",
            "| # | Phase | Action | Approval | Automatable |",
            "|---|-------|--------|----------|-------------|",
        ]
        for step in sorted(plan.steps, key=lambda s: s.order):
            appr = "yes" if step.requires_approval else "no"
            auto = "yes" if step.automatable else "no"
            lines.append(
                f"| {step.order} | {step.phase} | {step.action} | {appr} | {auto} |"
            )

    lines += ["", "## Audit log", ""]
    if report.audit_log:
        lines += [
            "| Timestamp | Stage | Agent | Model | Decision |",
            "|-----------|-------|-------|-------|----------|",
        ]
        for entry in report.audit_log:
            lines.append(
                f"| {entry.timestamp.isoformat()} | {entry.stage} | {entry.agent} | "
                f"{entry.model or '—'} | {entry.decision} |"
            )
    else:
        lines.append("_(empty)_")
    lines.append("")
    return "\n".join(lines)


def write_report(report: CaseReport, out_dir: str | Path) -> tuple[Path, Path]:
    """Write `<incident_id>.md` and `.json` into `out_dir`. Returns both paths."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    md_path = directory / f"{report.incident_id}.md"
    json_path = directory / f"{report.incident_id}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return md_path, json_path
