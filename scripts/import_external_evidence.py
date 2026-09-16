#!/usr/bin/env python3
"""Validate an opt-in external evidence envelope. Never fetches or runs tools.

Imported findings keep their original rule IDs and are never rewritten as
native ShipProof proof. Malformed, oversized, or stale envelopes exit 2.

Identity model (snapshot-identity/1.0): the envelope carries ``target_digest``
and ``config_digest`` claims, but those claims alone prove nothing. Callers
must supply expected digests computed from the bytes and effective options
actually reviewed (``--expect-target`` / ``--expect-config``, typically from
trusted CI or ``snapshot_identity.py``). A digest match establishes identity,
never authorship or correctness. Freshness is enforced only when the caller
sets ``--max-age-hours``; without an expiry policy an old timestamp alone
never rejects evidence whose identity still matches.

Usage:
  python scripts/import_external_evidence.py path/to/envelope.json [--json]
      [--expect-target HEX] [--expect-config HEX]
      [--max-age-hours HOURS] [--clock-skew-minutes MINUTES]
      [--allow-unverified] [--now ISO8601]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import stat as stat_module
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

MAX_BYTES = 2_000_000
MAX_FINDINGS = 500
MAX_MESSAGE = 512
MAX_LIMITATIONS = 32
MAX_DEPTH = 10
MAX_LINE = 10_000_000
DIGEST = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
SECRET_VALUE_RE = re.compile(r"(?i)(?:sk-|ghp_|github_pat_|xox[baprs]-|Bearer\s+)[A-Za-z0-9._\-]+")
ALLOWED_VERDICTS = frozenset(
    {"PASS", "PASS_WITH_EVIDENCE", "CONDITIONAL", "WARN", "REVIEW", "BLOCK"}
)
ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
TOP_FIELDS = frozenset(
    {
        "schema_version",
        "tool",
        "verdict",
        "limitations",
        "target_digest",
        "config_digest",
        "captured_at",
        "findings",
    }
)
TOOL_FIELDS = frozenset({"name", "version", "command"})
FINDING_FIELDS = frozenset({"original_rule_id", "severity", "path", "line", "message"})
PATH_ABSOLUTE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/)")


def redact(value: str) -> str:
    return SECRET_VALUE_RE.sub("[REDACTED]", value)


def require_str(payload: dict[str, Any], key: str, *, max_length: int) -> str:
    value = payload.get(key)
    if value is None or isinstance(value, bool):
        raise ValueError(f"{key} must be a non-empty string of at most {max_length} characters")
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


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate field: {key}")
        result[key] = value
    return result


def _check_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise ValueError("evidence envelope exceeds nesting depth limit")
    if isinstance(value, dict):
        for item in value.values():
            _check_depth(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _check_depth(item, depth + 1)


def read_envelope_bytes(path: Path) -> bytes:
    """Read the envelope without following a final symlink and detect replacement."""
    try:
        before = path.lstat()
        if not stat_module.S_ISREG(before.st_mode) or stat_module.S_ISLNK(before.st_mode):
            raise ValueError("evidence envelope must be a regular file, not a symlink or directory")
        if getattr(before, "st_file_attributes", 0) & 0x400:
            raise ValueError("evidence envelope must not be a reparse point")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat_module.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ValueError("evidence envelope changed during open")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(MAX_BYTES + 1)
            after = os.fstat(descriptor)
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("evidence envelope changed during read")
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ValueError(f"cannot read evidence envelope: {exc}") from exc
    if len(content) > MAX_BYTES:
        raise ValueError(f"evidence envelope exceeds {MAX_BYTES} bytes")
    return content


def check_evidence_path(path_text: str, *, field: str) -> str:
    if "\x00" in path_text:
        raise ValueError(f"{field} must not contain NUL")
    if PATH_ABSOLUTE.match(path_text):
        raise ValueError(f"{field} must be repository-relative, not absolute")
    segments = [
        segment for segment in path_text.replace("\\", "/").split("/") if segment not in ("", ".")
    ]
    if not segments or any(segment == ".." for segment in segments):
        raise ValueError(f"{field} must stay inside the reviewed root")
    return path_text


def load_envelope(
    path: Path,
    *,
    expect_target: str | None = None,
    expect_config: str | None = None,
    max_age_hours: float | None = None,
    clock_skew_minutes: float = 5.0,
    allow_unverified: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    raw = read_envelope_bytes(Path(path))
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"evidence envelope is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("evidence envelope must be an object")
    unknown_top = set(payload) - TOP_FIELDS
    if unknown_top:
        raise ValueError(f"evidence envelope has unknown fields: {sorted(unknown_top)}")
    _check_depth(payload)
    if payload.get("schema_version") != "1.0":
        raise ValueError("schema_version must be 1.0")
    tool = payload.get("tool")
    if not isinstance(tool, dict):
        raise ValueError("tool identity is required")
    unknown_tool = set(tool) - TOOL_FIELDS
    if unknown_tool:
        raise ValueError(f"tool has unknown fields: {sorted(unknown_tool)}")
    name = require_str(tool, "name", max_length=128)
    version = require_str(tool, "version", max_length=64)
    command = require_str(tool, "command", max_length=128)
    if name == "ShipProof":
        raise ValueError("imported evidence cannot claim the ShipProof tool identity")
    if not VERSION.fullmatch(version):
        raise ValueError("tool.version must be a semantic version")
    verdict = payload.get("verdict")
    if verdict is None or isinstance(verdict, bool) or verdict not in ALLOWED_VERDICTS:
        raise ValueError("verdict is missing or unsupported")
    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not limitations or len(limitations) > MAX_LIMITATIONS:
        raise ValueError("limitations must be a non-empty list")
    for item in limitations:
        if not isinstance(item, str) or not item or len(item) > 1024:
            raise ValueError("limitations must be non-empty strings")
    target_digest = require_str(payload, "target_digest", max_length=64)
    config_digest = require_str(payload, "config_digest", max_length=64)
    if not DIGEST.fullmatch(target_digest) or not DIGEST.fullmatch(config_digest):
        raise ValueError("target_digest and config_digest must be 64-character lowercase hex")
    captured = parse_timestamp(require_str(payload, "captured_at", max_length=64))
    current = now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc)
    for label, value in (
        ("clock-skew-minutes", clock_skew_minutes),
        ("max-age-hours", max_age_hours),
    ):
        if value is not None and (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 1_000_000
        ):
            raise ValueError(f"--{label} must be a finite non-negative number <= 1000000")
    skew = timedelta(minutes=clock_skew_minutes)
    if captured > current + skew:
        raise ValueError("captured_at is in the future beyond clock-skew allowance")
    age = current - captured
    stale = False
    if max_age_hours is not None:
        try:
            budget = timedelta(hours=float(max_age_hours))
        except (TypeError, ValueError) as exc:
            raise ValueError("--max-age-hours must be a non-negative number") from exc
        if budget < timedelta(0):
            raise ValueError("--max-age-hours must be a non-negative number")
        stale = age > budget + skew
    findings_in = payload.get("findings", [])
    if findings_in is None:
        findings_in = []
    if not isinstance(findings_in, list) or len(findings_in) > MAX_FINDINGS:
        raise ValueError(f"findings must be a list of at most {MAX_FINDINGS} items")
    findings = []
    for index, item in enumerate(findings_in):
        if not isinstance(item, dict):
            raise ValueError(f"findings[{index}] must be an object")
        unknown_finding = set(item) - FINDING_FIELDS
        if unknown_finding:
            raise ValueError(f"findings[{index}] has unknown fields: {sorted(unknown_finding)}")
        original = require_str(item, "original_rule_id", max_length=128)
        severity = item.get("severity")
        if severity is None or isinstance(severity, bool) or severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"findings[{index}].severity is unsupported")
        path_text = check_evidence_path(
            require_str(item, "path", max_length=512), field=f"findings[{index}].path"
        )
        line = item.get("line", 1)
        if isinstance(line, bool) or not isinstance(line, int) or not 1 <= line <= MAX_LINE:
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
    for field_name, expected in (
        ("target_digest", expect_target),
        ("config_digest", expect_config),
    ):
        if expected is not None and (
            not isinstance(expected, str) or not DIGEST.fullmatch(expected)
        ):
            raise ValueError(f"expected {field_name} must be 64-character lowercase hex")
    target_matches = expect_target is None or target_digest == expect_target
    config_matches = expect_config is None or config_digest == expect_config
    verification_attempted = bool(
        expect_target is not None or expect_config is not None or max_age_hours is not None
    )
    identity_matches = bool(
        (expect_target is not None and expect_config is not None)
        and target_matches
        and config_matches
    )
    reasons: list[str] = []
    if expect_target is not None and not target_matches:
        reasons.append("target_digest does not match the expected snapshot identity")
    if expect_config is not None and not config_matches:
        reasons.append("config_digest does not match the expected effective-policy identity")
    if stale:
        reasons.append("captured_at exceeds the caller max-age policy")
    if not verification_attempted or expect_target is None or expect_config is None:
        reasons.append(
            "both expected target and config identities are required; digest claims are unverified"
        )
    verified = bool(identity_matches and not stale)
    mismatch = bool(not target_matches or not config_matches)
    must_reject = bool((mismatch or stale) and not allow_unverified)
    if must_reject:
        detail = "; ".join(reasons) if reasons else "evidence identity is unverified"
        raise ValueError(f"stale or foreign evidence: {detail}")
    status = "verified" if verified else "unverified"
    # Identity matching alone never establishes trusted review evidence.
    gate_eligible = False
    resume_eligible = bool(verified)
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "command": "import-external-evidence"},
        "verdict": verdict,
        "imported_tool": {"name": name, "version": version, "command": command},
        "target_digest": target_digest,
        "config_digest": config_digest,
        "captured_at": captured.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "findings": findings,
        "identity_matches": identity_matches,
        "authorship_verified": False,
        "review_complete": False,
        "assessment_verified": False,
        "gate_eligible": gate_eligible,
        "resume_eligible": resume_eligible,
        "verification": {
            "status": status,
            "reasons": reasons
            or ["expected snapshot and policy identities match within freshness policy"],
            "notes": [
                "Digest equality establishes identity with the reviewed bytes, not authorship or correctness.",
                "Imported findings are external hypotheses; they never become native ShipProof proof.",
            ],
        },
        "limitations": [
            *[redact(item) for item in limitations],
            "Imported findings keep original_rule_id and are not native ShipProof proof.",
            "This adapter does not download, execute, or refresh the originating tool.",
            "Digest match does not prove the reviewer statement is true; authorship is unverified.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("envelope", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--expect-target", default=None)
    parser.add_argument("--expect-config", default=None)
    parser.add_argument("--max-age-hours", type=float, default=None)
    parser.add_argument("--clock-skew-minutes", type=float, default=5.0)
    parser.add_argument("--allow-unverified", action="store_true")
    parser.add_argument("--now", default=None, help="ISO-8601 override for tests")
    arguments = parser.parse_args()
    try:
        moment = parse_timestamp(arguments.now) if arguments.now else None
        report = load_envelope(
            arguments.envelope,
            expect_target=arguments.expect_target,
            expect_config=arguments.expect_config,
            max_age_hours=arguments.max_age_hours,
            clock_skew_minutes=arguments.clock_skew_minutes,
            allow_unverified=arguments.allow_unverified,
            now=moment,
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"external evidence: {exc}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(report, indent=2))
    else:
        print(
            f"imported {report['imported_tool']['name']}@{report['imported_tool']['version']} "
            f"findings={len(report['findings'])} verdict={report['verdict']} "
            f"verification={report['verification']['status']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
