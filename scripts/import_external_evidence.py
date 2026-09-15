#!/usr/bin/env python3
"""Validate an opt-in external evidence envelope. Never fetches or runs tools.

Imported findings keep their original rule IDs and are never rewritten as
native ShipProof proof. Malformed, oversized, or stale envelopes exit 2.

Usage:
  python scripts/import_external_evidence.py path/to/envelope.json [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000
MAX_FINDINGS = 500
MAX_MESSAGE = 512
MAX_LIMITATIONS = 32
DIGEST = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SECRET_VALUE_RE = re.compile(r"(?i)(?:sk-|ghp_|github_pat_|xox[baprs]-|Bearer\s+)[A-Za-z0-9._\-]+")
ALLOWED_VERDICTS = frozenset(
    {"PASS", "PASS_WITH_EVIDENCE", "CONDITIONAL", "WARN", "REVIEW", "BLOCK"}
)
ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


def redact(value: str) -> str:
    return SECRET_VALUE_RE.sub("[REDACTED]", value)


def require_str(payload: dict[str, Any], key: str, *, max_length: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{key} must be a non-empty string of at most {max_length} characters")
    return value


def parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("captured_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("captured_at must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_envelope(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(f"evidence envelope exceeds {MAX_BYTES} bytes")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("evidence envelope must be an object")
    if payload.get("schema_version") != "1.0":
        raise ValueError("schema_version must be 1.0")
    tool = payload.get("tool")
    if not isinstance(tool, dict):
        raise ValueError("tool identity is required")
    name = require_str(tool, "name", max_length=128)
    version = require_str(tool, "version", max_length=64)
    command = require_str(tool, "command", max_length=128)
    if name == "ShipProof":
        raise ValueError("imported evidence cannot claim the ShipProof tool identity")
    if not VERSION.fullmatch(version):
        raise ValueError("tool.version must be a semantic version")
    verdict = payload.get("verdict")
    if verdict not in ALLOWED_VERDICTS:
        raise ValueError("verdict is missing or unsupported")
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not limitations or len(limitations) > MAX_LIMITATIONS:
        raise ValueError("limitations must be a non-empty list")
    if not all(isinstance(item, str) and item for item in limitations):
        raise ValueError("limitations must be non-empty strings")
    target_digest = require_str(payload, "target_digest", max_length=64)
    config_digest = require_str(payload, "config_digest", max_length=64)
    if not DIGEST.fullmatch(target_digest) or not DIGEST.fullmatch(config_digest):
        raise ValueError("target_digest and config_digest must be 64-character lowercase hex")
    captured = parse_timestamp(require_str(payload, "captured_at", max_length=64))
    findings_in = payload.get("findings") or []
    if not isinstance(findings_in, list) or len(findings_in) > MAX_FINDINGS:
        raise ValueError(f"findings must be a list of at most {MAX_FINDINGS} items")
    findings = []
    for index, item in enumerate(findings_in):
        if not isinstance(item, dict):
            raise ValueError(f"findings[{index}] must be an object")
        original = require_str(item, "original_rule_id", max_length=128)
        severity = item.get("severity")
        if severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"findings[{index}].severity is unsupported")
        path_text = require_str(item, "path", max_length=512)
        line = item.get("line", 1)
        if not isinstance(line, int) or line < 1:
            raise ValueError(f"findings[{index}].line must be a positive integer")
        message = require_str(item, "message", max_length=MAX_MESSAGE)
        findings.append(
            {
                "original_rule_id": original,
                "severity": severity,
                "path": path_text,
                "line": line,
                "message": redact(message),
                "imported": True,
                "proof_level": "external",
            }
        )
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "command": "import-external-evidence"},
        "verdict": verdict,
        "imported_tool": {"name": name, "version": version, "command": command},
        "target_digest": target_digest,
        "config_digest": config_digest,
        "captured_at": captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": findings,
        "limitations": [
            *[redact(item) for item in limitations],
            "Imported findings keep original_rule_id and are not native ShipProof proof.",
            "This adapter does not download, execute, or refresh the originating tool.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("envelope", type=Path)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    try:
        report = load_envelope(arguments.envelope)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"external evidence: {exc}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"imported {report['imported_tool']['name']}@{report['imported_tool']['version']} "
            f"findings={len(report['findings'])} verdict={report['verdict']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
