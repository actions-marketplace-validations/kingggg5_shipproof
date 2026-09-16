#!/usr/bin/env python3
"""Append-only triage trail CLI (maintainer workflow, never default path).

Subcommands read/write a hash-chained JSONL trail. Findings are preserved;
assessments append; quarantines and budgets are enforced by triage_trail.

Exit codes: 0 ok, 1 fix not verified (verify-fix only), 2 malformed/unavailable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import triage_trail as trail  # noqa: E402


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON {path}: {exc}") from exc


def command_append_finding(arguments: argparse.Namespace) -> int:
    store = trail.Trail(arguments.trail)
    envelope = trail.append_raw_finding(store, load_json(arguments.finding))  # type: ignore[arg-type]
    store.save()
    print(json.dumps({"hash": envelope["hash"]}, indent=2))
    return 0


def command_append_assessment(arguments: argparse.Namespace) -> int:
    store = trail.Trail(arguments.trail)
    envelope = trail.append_assessment(store, load_json(arguments.assessment))  # type: ignore[arg-type]
    store.save()
    print(json.dumps({"kind": envelope["kind"], "hash": envelope["hash"]}, indent=2))
    return 0


def command_suggest_duplicates(arguments: argparse.Namespace) -> int:
    store = trail.Trail(arguments.trail)
    assessments = [
        envelope["record"] for envelope in store.records if envelope["kind"] == "assessment"
    ]
    print(json.dumps(trail.suggest_duplicate_groups(assessments), indent=2))
    return 0


def command_verify_fix(arguments: argparse.Namespace) -> int:
    rescan = load_json(arguments.rescan)
    if not isinstance(rescan, dict):
        raise ValueError("--rescan must be a JSON object")
    report = trail.verify_fix(
        fingerprint=arguments.fingerprint,
        rescan_findings=list(rescan.get("finding_fingerprints", []) or []),
        new_blocking=list(rescan.get("new_blocking", []) or []),
        test_command=arguments.test_command or "",
        test_exit_code=arguments.test_exit_code,
    )
    print(json.dumps(report, indent=2))
    return 0 if report["verified"] else 1


def command_counts(arguments: argparse.Namespace) -> int:
    store = trail.Trail(arguments.trail)
    print(json.dumps(store.counts(), indent=2))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trail", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    finding = sub.add_parser("append-finding")
    finding.add_argument("--finding", type=Path, required=True)
    finding.set_defaults(handler=command_append_finding)
    assessment = sub.add_parser("append-assessment")
    assessment.add_argument("--assessment", type=Path, required=True)
    assessment.set_defaults(handler=command_append_assessment)
    duplicates = sub.add_parser("suggest-duplicates")
    duplicates.set_defaults(handler=command_suggest_duplicates)
    verify = sub.add_parser("verify-fix")
    verify.add_argument("--fingerprint", required=True)
    verify.add_argument("--rescan", type=Path, required=True)
    verify.add_argument("--test-command", default="")
    verify.add_argument("--test-exit-code", type=int, default=None)
    verify.set_defaults(handler=command_verify_fix)
    counts = sub.add_parser("counts")
    counts.set_defaults(handler=command_counts)
    arguments = parser.parse_args()
    try:
        return int(arguments.handler(arguments))
    except (OSError, ValueError, TypeError) as exc:
        print(f"triage: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
