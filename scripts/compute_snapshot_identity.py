#!/usr/bin/env python3
"""Compute a canonical snapshot identity for the exact bytes reviewed.

Offline, read-only, dependency-free. Prints JSON with ``target_digest`` and
``config_digest`` that callers feed back to ``import_external_evidence.py``
via ``--expect-target`` / ``--expect-config`` (or to ``shipproof gate
evidence --import`` via ``--expect-target`` / ``--expect-config``).

The expected values must be computed from the bytes and effective options
actually reviewed -- never copied from the envelope being verified.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import snapshot_identity as identity  # noqa: E402

try:
    from scan_repo import VERSION as SCANNER_VERSION
except ImportError:  # pragma: no cover - standalone fallback
    SCANNER_VERSION = "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--policy-json", default="{}", help="effective policy as JSON object")
    parser.add_argument("--max-file-bytes", type=int, default=1_000_000)
    parser.add_argument("--rules-identity", default=None)
    parser.add_argument("--scanner-version", default=None)
    arguments = parser.parse_args()
    try:
        policy = json.loads(arguments.policy_json)
    except json.JSONDecodeError as exc:
        print(f"snapshot identity: invalid --policy-json: {exc}", file=sys.stderr)
        return 2
    if not isinstance(policy, dict):
        print("snapshot identity: --policy-json must be a JSON object", file=sys.stderr)
        return 2
    rules_identity = arguments.rules_identity
    if rules_identity is None:
        rules_identity = identity.scanner_code_identity()
    try:
        report = identity.snapshot_identity(
            arguments.root,
            max_file_bytes=arguments.max_file_bytes,
            policy=policy,
            scanner_version=arguments.scanner_version or f"shipproof-scan/{SCANNER_VERSION}",
            rules_identity=rules_identity,
        )
    except (OSError, ValueError) as exc:
        print(f"snapshot identity: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
