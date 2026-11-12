"""`soar-tool`: the deterministic, offline plumbing behind the console mode.

This is the half of the pipeline that must NOT be a language model: contract
validation, offline threat-intel and ATT&CK lookups, playbook selection, and
report rendering. Nothing here touches the network unless `ABUSEIPDB_API_KEY` is
set.

Subcommands
-----------
    soar-tool validate --schema incident --in incident.json
    soar-tool intel 45.133.1.77 --type ip
    soar-tool attack verify T1566
    soar-tool attack search phishing
    soar-tool playbook phishing
    soar-tool report --case case.json --out reports/

Every subcommand emits JSON on stdout (so the caller can parse it) and uses the exit
code as the coarse signal: 0 = handled, 1 = invalid input / validation failure, 2 =
usage error. `validate` prints the pydantic error verbatim on failure so the console
session can feed it straight back into its retry.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from orchestrator.reporting import write_report
from orchestrator.schemas import (
    AuditEntry,
    CaseReport,
    Incident,
    Investigation,
    RawEvent,
    ResponsePlan,
)
from orchestrator.tools import intel

# Schema name (as used on the CLI) -> model. Kebab-case keys match how a human
# would type them; the console slash-commands pass the same strings.
SCHEMAS: dict[str, type[BaseModel]] = {
    "raw-event": RawEvent,
    "incident": Incident,
    "investigation": Investigation,
    "response-plan": ResponsePlan,
    "case-report": CaseReport,
    "audit-entry": AuditEntry,
}


def _read_input(spec: str) -> str:
    """Read a JSON payload from a file path, or from stdin when spec is '-'."""
    if spec == "-":
        return sys.stdin.read()
    return Path(spec).read_text(encoding="utf-8")


def _emit(payload: Any) -> None:
    print(json.dumps(payload, indent=2, default=str))


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------
def cmd_validate(args: argparse.Namespace) -> int:
    model = SCHEMAS[args.schema]
    try:
        raw = json.loads(_read_input(args.in_))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read/parse input: {exc}", file=sys.stderr)
        return 1
    try:
        obj = model.model_validate(raw)
    except ValidationError as exc:
        # Print the pydantic error verbatim so the console session can correct
        # itself on the next attempt, exactly like the API-mode retry loop.
        print(f"validation failed for {args.schema}:\n{exc}", file=sys.stderr)
        return 1
    _emit(
        {
            "status": "ok",
            "schema": args.schema,
            "normalized": obj.model_dump(mode="json"),
        }
    )
    return 0


# --------------------------------------------------------------------------
# intel
# --------------------------------------------------------------------------
def cmd_intel(args: argparse.Namespace) -> int:
    _emit(intel.lookup_reputation(args.indicator, args.type))
    return 0


# --------------------------------------------------------------------------
# attack
# --------------------------------------------------------------------------
def cmd_attack(args: argparse.Namespace) -> int:
    if args.attack_cmd == "verify":
        _emit(intel.verify_technique(args.technique_id))
    else:
        _emit(intel.search_techniques(args.query))
    return 0


# --------------------------------------------------------------------------
# playbook
# --------------------------------------------------------------------------
def cmd_playbook(args: argparse.Namespace) -> int:
    entry = intel.get_playbook(args.category)
    if entry is None:
        print(
            f"no playbook for category {args.category!r}; "
            f"available: {', '.join(intel.playbook_categories())}",
            file=sys.stderr,
        )
        return 1
    _emit(entry)
    return 0


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def cmd_report(args: argparse.Namespace) -> int:
    try:
        raw = json.loads(_read_input(args.case))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"could not read/parse case: {exc}", file=sys.stderr)
        return 1
    try:
        report = CaseReport.model_validate(raw)
    except ValidationError as exc:
        print(f"invalid CaseReport:\n{exc}", file=sys.stderr)
        return 1

    md_path, json_path = write_report(report, args.out)
    _emit({"status": "ok", "markdown": str(md_path), "json": str(json_path)})
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soar-tool",
        description="Deterministic, offline plumbing for the console mode "
        "(validation, threat-intel, ATT&CK, playbooks, reporting). No API key needed.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="validate JSON against a pipeline contract")
    p_val.add_argument("--schema", required=True, choices=sorted(SCHEMAS))
    p_val.add_argument(
        "--in", dest="in_", required=True, help="input JSON path, or '-' for stdin"
    )
    p_val.set_defaults(func=cmd_validate)

    p_intel = sub.add_parser("intel", help="offline reputation lookup for one indicator")
    p_intel.add_argument("indicator")
    p_intel.add_argument("--type", help="optional observable type hint (ip/domain/...)")
    p_intel.set_defaults(func=cmd_intel)

    p_att = sub.add_parser("attack", help="ATT&CK catalog verify/search")
    att_sub = p_att.add_subparsers(dest="attack_cmd", required=True)
    p_ver = att_sub.add_parser(
        "verify", help="check a technique id exists in the catalog"
    )
    p_ver.add_argument("technique_id")
    p_ver.set_defaults(func=cmd_attack)
    p_sea = att_sub.add_parser("search", help="search techniques by id/name/tactic")
    p_sea.add_argument("query")
    p_sea.set_defaults(func=cmd_attack)

    p_pb = sub.add_parser("playbook", help="emit the playbook for an incident category")
    p_pb.add_argument("category")
    p_pb.set_defaults(func=cmd_playbook)

    p_rep = sub.add_parser(
        "report", help="validate a CaseReport and render Markdown+JSON"
    )
    p_rep.add_argument(
        "--case", required=True, help="CaseReport JSON path, or '-' for stdin"
    )
    p_rep.add_argument(
        "--out", default="reports", help="output directory (default: reports/)"
    )
    p_rep.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
