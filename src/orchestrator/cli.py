"""`soar-orchestrator`: the API-mode entry point.

Runs a scenario through detect -> investigate -> respond and writes the case
report. This is the mode that needs `ANTHROPIC_API_KEY`; if you would rather not
use one, the deterministic half still runs offline through `soar-tool`.

    soar-orchestrator run data/scenarios/phishing-01.json
    soar-orchestrator scenarios
    soar-orchestrator playbooks
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from orchestrator._llm import StructuredLLMClient
from orchestrator.orchestrator import OrchestratorError, load_events, run_case
from orchestrator.reporting import write_report
from orchestrator.tools import intel

EXIT_OK = 0
EXIT_FAILED = 1


def _build_client() -> StructuredLLMClient:
    """Create a structured LLM client, or explain precisely what is missing.

    Kept out of the agents on purpose: they take a client, they never make one,
    which is what lets every test run offline.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise SystemExit(
            "ANTHROPIC_API_KEY is not set.\n"
            "Either export it (see .env.example), or run the deterministic half "
            "without a key:\n"
            "    soar-tool validate --schema incident --in incident.json"
        )
    return StructuredLLMClient()


def _summarize(report) -> str:
    lines = [
        f"case {report.incident_id}: {report.final_state}",
        f"  incident   : {report.incident.title}",
        (
            f"  category   : {report.incident.category} / {report.incident.severity} "
            f"(confidence {report.incident.confidence:.2f})"
        ),
    ]
    if report.incident.false_positive_reason:
        lines.append(f"  dismissed  : {report.incident.false_positive_reason}")
    if report.investigation is not None:
        techniques = ", ".join(
            t.technique_id for t in report.investigation.mitre_techniques
        )
        lines.append(f"  ATT&CK     : {techniques or '(none verified)'}")
    if report.response_plan is not None:
        approvals = sum(
            1 for s in report.response_plan.steps if s.requires_approval
        )
        lines.append(
            f"  plan       : {len(report.response_plan.steps)} step(s), "
            f"{approvals} needing human approval"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------
def cmd_run(args: argparse.Namespace) -> int:
    scenario = Path(args.scenario)
    try:
        events = load_events(scenario)
    except OrchestratorError as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED

    client = _build_client()
    try:
        report = run_case(
            events,
            llm_client=client,
            incident_id=scenario.stem,
        )
    except OrchestratorError as exc:
        print(exc, file=sys.stderr)
        return EXIT_FAILED

    print(_summarize(report))
    if not args.no_report:
        md_path, json_path = write_report(report, args.out)
        print(f"  report     : {md_path}  |  {json_path}")
    return EXIT_OK


def cmd_scenarios(args: argparse.Namespace) -> int:
    directory = intel.data_dir() / "scenarios"
    for path in sorted(directory.glob("*.json")):
        if path.name == "labels.json":
            continue
        try:
            events = load_events(path)
        except OrchestratorError as exc:
            print(f"{path.stem:<26} INVALID: {exc}", file=sys.stderr)
            continue
        print(f"{path.stem:<26} {len(events):>2} event(s)  {events[0].source}")
    return EXIT_OK


def cmd_playbooks(args: argparse.Namespace) -> int:
    for category in intel.playbook_categories():
        playbook = intel.get_playbook(category) or {}
        steps = playbook.get("steps", [])
        print(f"{category:<18} {len(steps):>2} step(s)  {playbook.get('playbook_name')}")
    return EXIT_OK


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soar-orchestrator",
        description="Run a security scenario through the detect -> investigate -> "
        "respond pipeline and write an auditable case report.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run one scenario end to end")
    p_run.add_argument("scenario", help="path to a scenario JSON file (RawEvent[])")
    p_run.add_argument("--out", default="reports", help="report directory")
    p_run.add_argument(
        "--model",
        default=None,
        help="override the model for every agent (default: haiku detector, "
        "sonnet investigator/responder)",
    )
    p_run.add_argument(
        "--no-report", action="store_true", help="print the summary but write no files"
    )
    p_run.set_defaults(func=cmd_run)

    p_sc = sub.add_parser("scenarios", help="list the bundled scenarios")
    p_sc.set_defaults(func=cmd_scenarios)

    p_pb = sub.add_parser("playbooks", help="list the bundled response playbooks")
    p_pb.set_defaults(func=cmd_playbooks)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
