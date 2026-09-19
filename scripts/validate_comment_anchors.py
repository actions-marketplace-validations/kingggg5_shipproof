#!/usr/bin/env python3
"""Validate external review comment anchors against the reviewed bytes.

Offline, read-only, dependency-free. Reads a ``comment-anchor/1.0`` JSON
document and reports per-comment ``resolved`` / ``unresolved`` status. Only
``resolved`` anchors are ``inline_eligible``; unresolved anchors are kept as
review questions and must never be auto-published as inline findings.

Exit codes: 0 = report produced (check counts.unresolved before publishing),
1 = --fail-on-unresolved and at least one anchor is unresolved,
2 = malformed input or unavailable evidence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import comment_anchors as anchors  # noqa: E402

MAX_BYTES = 2_000_000


def load_document(path: Path) -> dict:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"cannot read anchor document: {exc}") from exc
    if size > MAX_BYTES:
        raise ValueError(f"anchor document exceeds {MAX_BYTES} bytes")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"anchor document is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("anchor document must be an object")
    unknown = set(payload) - {"schema_version", "revision", "comments"}
    if unknown:
        raise ValueError(f"anchor document has unknown fields: {sorted(unknown)}")
    if payload.get("schema_version") != "comment-anchor/1.0":
        raise ValueError("schema_version must be comment-anchor/1.0")
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--old-root", type=Path, default=None)
    parser.add_argument("--scope", action="append", default=None)
    parser.add_argument("--expect-revision", default=None)
    parser.add_argument("--fail-on-unresolved", action="store_true")
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    try:
        payload = load_document(arguments.document)
        report = anchors.validate_comments(
            payload.get("comments", []),
            new_root=arguments.root,
            old_root=arguments.old_root,
            new_selected=arguments.scope,
            old_selected=arguments.scope,
            revision=payload.get("revision", ""),
            expect_revision=arguments.expect_revision,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(f"comment anchors: {exc}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(report, indent=2))
    else:
        counts = report["counts"]
        print(
            f"anchors resolved={counts['resolved']} "
            f"unresolved={counts['unresolved']} "
            f"revision_matches={report['revision_matches']}"
        )
    if arguments.fail_on_unresolved and report["counts"]["unresolved"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
