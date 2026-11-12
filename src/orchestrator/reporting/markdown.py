"""Render a `CaseReport` as an analyst-readable Markdown brief.

Both run modes end here: `soar-orchestrator run` calls `write_report()` directly,
and the console mode reaches the same function through `soar-tool report`. The
audit log is rendered last and in full — the point of the whole pipeline is that
someone can read *why* each conclusion was reached, not just what it was.
"""

from __future__ import annotations

import re
from pathlib import Path

from orchestrator.schemas import CaseReport

# incident_id becomes a file name component: collapse everything that is not a
# conservative filename character, so a model-invented id like "../../evil" can
# never write outside the report directory.
_UNSAFE_FILENAME = re.compile("[^A-Za-z0-9._-]+")


def _safe_component(value: str) -> str:
    cleaned = _UNSAFE_FILENAME.sub("_", value).strip("._")
    return cleaned or "case"


def _escape_cell(text: str) -> str:
    """Keep one-line table cells intact: pipes escaped, newlines flattened."""
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _format_probability(value: float | None) -> str:
    return f"{value:.2f}" if value is not None else "—"


def _format_choice_distribution(probabilities: dict[str, float]) -> str:
    if not probabilities:
        return "—"
    return ", ".join(
        f"{choice}={probability:.2f}"
        for choice, probability in sorted(probabilities.items())
    )


def _format_score(score: float | None, confidence: float | None) -> str:
    if score is None:
        return "—"
    confidence_text = f"{confidence:.2f}" if confidence is not None else "—"
    return f"{score:.2f} / 3.00 — Confidence: {confidence_text}"


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
        f"- **Confidence:** {inc.confidence:.2f}",
        f"- **Escalated:** {'yes' if inc.escalate else 'no'}",
        f"- **Summary:** {inc.summary}",
    ]
    if inc.false_positive_reason:
        lines.append(f"- **False positive reason:** {inc.false_positive_reason}")
    if inc.initial_indicators:
        lines.append("- **Initial indicators:**")
        lines += [f"  - `{value}`" for value in inc.initial_indicators]

    telemetry = inc.system_one_telemetry
    if telemetry is not None:
        lines += [
            "",
            "## System One (Jev) Calibrated Telemetry",
            "",
            "| Noul | Choice distribution | Score |",
            "|------|---------------------|-------|",
            (
                f"| prompt-injection={_format_probability(telemetry.prompt_injection_noul)}, "
                f"threat={_format_probability(telemetry.is_threat_noul)}, "
                f"contained={_format_probability(telemetry.already_contained_noul)}, "
                f"category-fit={_format_probability(telemetry.category_fits_noul)} | "
                f"{_format_choice_distribution(telemetry.category_probabilities)} | "
                f"{_format_score(telemetry.severity_score, telemetry.severity_confidence)} |"
            ),
        ]
        if telemetry.grounding_nouls:
            grounding = ", ".join(
                f"{name}={_format_probability(score)}"
                for name, score in sorted(telemetry.grounding_nouls.items())
            )
            lines.append(f"- **Grounding Nouls:** {grounding}")

    if report.investigation is not None:
        inv = report.investigation
        lines += [
            "",
            "## Investigation",
            f"- **Hypothesis:** {inv.hypothesis}",
        ]
        if inv.confidence is not None:
            lines.append(f"- **Confidence:** {inv.confidence:.2f}")
        lines += [
            f"- **Attack chain:** {inv.attack_chain_summary or '—'}",
            f"- **Recommended severity:** {inv.recommended_severity}",
        ]
        if inv.mitre_techniques:
            lines.append("- **ATT&CK techniques:**")
            lines += [
                f"  - {t.technique_id} {t.name} ({t.tactic})"
                + (f" — {t.evidence}" if t.evidence else "")
                for t in inv.mitre_techniques
            ]
        if inv.enriched_iocs:
            lines.append("- **Enriched IOCs:**")
            lines += [
                f"  - `{ioc.type or '?'}` {ioc.indicator} → **{ioc.reputation}** ({ioc.source})"
                for ioc in inv.enriched_iocs
            ]
        if inv.affected_assets:
            lines.append(f"- **Affected assets:** {', '.join(inv.affected_assets)}")
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
            "| # | Phase | Action | Approval | Automatable | Blast radius | HITL Noul |",
            "|---|-------|--------|----------|-------------|--------------|-----------|",
        ]
        for step in sorted(plan.steps, key=lambda s: s.order):
            appr = "yes" if step.requires_approval else "no"
            auto = "yes" if step.automatable else "no"
            blast = (
                f"{step.blast_radius_score:.2f}"
                if step.blast_radius_score is not None
                else "—"
            )
            hitl = f"{step.hitl_noul:.2f}" if step.hitl_noul is not None else "—"
            lines.append(
                f"| {step.order} | {step.phase} | {_escape_cell(step.action)} | "
                f"{appr} | {auto} | {blast} | {hitl} |"
            )

    lines += ["", "## Audit log", ""]
    if report.audit_log:
        lines += [
            "| Timestamp | Stage | Actor | Action | Details |",
            "|-----------|-------|-------|--------|---------|",
        ]
        for entry in report.audit_log:
            lines.append(
                f"| {entry.timestamp.isoformat()} | {entry.stage} | "
                f"{_escape_cell(entry.actor)} | {_escape_cell(entry.action)} | "
                f"{_escape_cell(entry.details) or '—'} |"
            )
    else:
        lines.append("_(empty)_")
    lines.append("")
    return "\n".join(lines)


def write_report(report: CaseReport, out_dir: str | Path) -> tuple[Path, Path]:
    """Write `<incident_id>.md` and `.json` into `out_dir`. Returns both paths."""
    directory = Path(out_dir)
    directory.mkdir(parents=True, exist_ok=True)
    safe_id = _safe_component(report.incident_id)
    md_path = directory / f"{safe_id}.md"
    json_path = directory / f"{safe_id}.json"
    md_path.write_text(render_markdown(report), encoding="utf-8")
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return md_path, json_path
