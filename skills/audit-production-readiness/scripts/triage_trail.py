#!/usr/bin/env python3
"""Recorded verification pass and triage trail (Q06).

Offline, dependency-free. Native scanner findings and external hypotheses stay
separate: an external assessment keeps its original rule ID and can never
become native ShipProof proof (no SPxxx ID, no L1/L2 proof level).

The trail is append-only JSONL with a hash chain: the raw finding is preserved
and every assessment appends. Raw and triaged views reconcile exactly.
Assessment vocabulary matches finding_labels (true_positive / false_positive /
needs_context / duplicate); reviewer type and confirmation travel separately.

Safety rules enforced here, not by convention:
  - verification failures and prompt-injection attempts keep the findings and
    quarantine the assessment instead;
  - a round budget caps reads/calls/time/output/tokens; retries never reset it;
  - duplicate groups are suggested deterministically but never auto-merged;
  - a fix is verified only with a clean re-scan AND an attested passing test.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from scan_repo import safe_write_text
from snapshot_identity import read_bytes_guarded

TRAIL_VERSION = "triage-trail/1.0"
ASSESSMENT_VERSION = "triage-assessment/1.0"
# Must equal finding_labels.ALLOWED_LABELS; a test enforces this.
VERDICTS = frozenset({"true_positive", "false_positive", "needs_context", "duplicate"})
REVIEWER_TYPES = frozenset({"human", "model", "deterministic"})
# Heuristic tripwires for review text that tries to steer the tool. This is a
# fail-closed tripwire, not a jailbreak-proof filter: hits quarantine the
# assessment while the findings stand.
INJECTION_PATTERNS = (
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\b"),
    re.compile(r"(?i)\bdisable\s+(this\s+)?rule\b"),
    re.compile(r"(?i)\bset\s+fail_on\s+to\s+none\b"),
    re.compile(r"(?i)\blower\s+the\s+(threshold|severity)\b"),
    re.compile(r"(?i)\bmark\s+(this|all)\s+findings?\s+as\s+false\b"),
    re.compile(r"(?i)\bgrant\s+(me|us)\s+admin\b"),
    re.compile(r"(?i)\bsuppress\s+all\s+findings\b"),
)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_hash(previous: str, record: dict[str, Any]) -> str:
    return hashlib.sha256((previous + "\x00" + _canonical(record)).encode("utf-8")).hexdigest()


def envelope_hash(previous: str, envelope: dict[str, Any]) -> str:
    return record_hash(previous, {key: value for key, value in envelope.items() if key != "hash"})


def check_assessment(item: Any) -> dict[str, Any]:
    """Validate an assessment shape. Returns a normalized copy."""
    if not isinstance(item, dict):
        raise ValueError("assessment must be an object")
    allowed = {
        "fingerprint",
        "rule_id",
        "imported",
        "original_rule_id",
        "proof_level",
        "reviewer_type",
        "confirmation",
        "verdict",
        "trigger",
        "evidence",
        "counterevidence",
        "uncertainty",
        "remediation",
        "test_method",
    }
    unknown = set(item) - allowed
    if unknown:
        raise ValueError(f"assessment has unknown fields: {sorted(unknown)}")
    fingerprint = item.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{8,64}", fingerprint):
        raise ValueError("fingerprint must be lowercase hex")
    imported = item.get("imported", False)
    if not isinstance(imported, bool):
        raise ValueError("imported must be a boolean")
    if imported:
        original = item.get("original_rule_id")
        if not isinstance(original, str) or not original:
            raise ValueError("imported assessments must keep original_rule_id")
        if "rule_id" in item:
            raise ValueError("imported assessments must not claim a native rule_id")
        if item.get("proof_level") in {"L1", "L2"}:
            raise ValueError("imported assessments must never claim L1/L2 proof")
    else:
        rule_id = item.get("rule_id")
        if not isinstance(rule_id, str) or not re.fullmatch(r"SP[0-9]{3}", rule_id):
            raise ValueError("native assessments need an SPxxx rule_id")
    reviewer_type = item.get("reviewer_type")
    if reviewer_type not in REVIEWER_TYPES:
        raise ValueError(f"reviewer_type must be one of {sorted(REVIEWER_TYPES)}")
    if item.get("confirmation") not in {"confirmed", "unconfirmed"}:
        raise ValueError("confirmation must be confirmed or unconfirmed")
    if item.get("reviewer_type") != "human" and item.get("confirmation") == "confirmed":
        raise ValueError("only human review can confirm an assessment")
    if item.get("verdict") not in VERDICTS:
        raise ValueError(f"verdict must be one of {sorted(VERDICTS)}")
    for field_name in ("trigger", "uncertainty", "remediation", "test_method"):
        value = item.get(field_name, "")
        if not isinstance(value, str) or len(value) > 2000:
            raise ValueError(f"{field_name} must be a string of at most 2000 characters")
    for field_name in ("evidence", "counterevidence"):
        values = item.get(field_name, [])
        if not isinstance(values, list) or any(
            not isinstance(entry, str) or not entry or len(entry) > 2000 for entry in values
        ):
            raise ValueError(f"{field_name} must be a list of non-empty strings")
    if not item.get("trigger"):
        raise ValueError("assessments without a trigger stay needs-context upstream")
    normalized = {key: item.get(key) for key in sorted(allowed) if key in item}
    normalized.setdefault("imported", False)
    normalized.setdefault("evidence", [])
    normalized.setdefault("counterevidence", [])
    return normalized


def quarantine_reason(assessment: dict[str, Any]) -> str | None:
    """Return a reason when review text trips an injection tripwire."""
    haystacks = [
        str(assessment.get("trigger", "")),
        str(assessment.get("remediation", "")),
        str(assessment.get("test_method", "")),
        *[str(entry) for entry in assessment.get("evidence", [])],
    ]
    for text in haystacks:
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                return f"review text matches policy-steering pattern {pattern.pattern}"
    return None


@dataclass
class RoundBudget:
    max_reads: int = 50
    max_calls: int = 20
    max_seconds: float = 600.0
    max_output_bytes: int = 200000
    max_tokens_estimate: int = 50000
    reads: int = 0
    calls: int = 0
    started: float = field(default_factory=time.monotonic)
    output_bytes: int = 0
    tokens_estimate: int = 0
    exhausted: list[str] = field(default_factory=list)

    def consume(
        self,
        *,
        reads: int = 0,
        calls: int = 0,
        output_bytes: int = 0,
        tokens_estimate: int = 0,
    ) -> list[str]:
        """Charge usage. Monotonic: retries never reset the budget."""
        if any(
            type(value) is not int or value < 0
            for value in (reads, calls, output_bytes, tokens_estimate)
        ):
            raise ValueError("budget charges must be non-negative integers")
        self.reads += reads
        self.calls += calls
        self.output_bytes += output_bytes
        self.tokens_estimate += tokens_estimate
        elapsed = time.monotonic() - self.started
        for name, used, limit in (
            ("reads", self.reads, self.max_reads),
            ("calls", self.calls, self.max_calls),
            ("time", elapsed, self.max_seconds),
            ("output", self.output_bytes, self.max_output_bytes),
            ("tokens", self.tokens_estimate, self.max_tokens_estimate),
        ):
            if used > limit and name not in self.exhausted:
                self.exhausted.append(name)
        return list(self.exhausted)

    def as_dict(self) -> dict[str, Any]:
        return {
            "max_reads": self.max_reads,
            "max_calls": self.max_calls,
            "max_seconds": self.max_seconds,
            "max_output_bytes": self.max_output_bytes,
            "max_tokens_estimate": self.max_tokens_estimate,
            "used_reads": self.reads,
            "used_calls": self.calls,
            "used_output_bytes": self.output_bytes,
            "used_tokens_estimate": self.tokens_estimate,
            "exhausted": list(self.exhausted),
        }


class Trail:
    """Append-only hash-chained triage trail over one JSONL file."""

    def __init__(self, path: Path):
        self.path = path
        self.records: list[dict[str, Any]] = []
        self.head = "genesis"
        self.loaded_bytes = None
        if path.is_file():
            self.loaded_bytes = read_bytes_guarded(path, 8_000_000)
            for line_number, raw in enumerate(self.loaded_bytes.decode("utf-8").splitlines(), 1):
                if not raw.strip():
                    continue
                try:
                    envelope = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"trail line {line_number} is not JSON") from exc
                if not isinstance(envelope, dict) or not isinstance(envelope.get("record"), dict):
                    raise ValueError(f"trail line {line_number} has invalid shape")
                digest = envelope.get("hash")
                if (
                    envelope.get("previous") != self.head
                    or envelope.get("trail_version") != TRAIL_VERSION
                    or envelope.get("kind")
                    not in {"raw_finding", "assessment", "quarantined_assessment"}
                    or envelope_hash(self.head, envelope) != digest
                ):
                    raise ValueError(f"trail line {line_number} breaks the hash chain")
                self.head = str(digest)
                self.records.append(envelope)

    def append(self, kind: str, record: dict[str, Any]) -> dict[str, Any]:
        envelope = {
            "trail_version": TRAIL_VERSION,
            "kind": kind,
            "record": record,
            "previous": self.head,
        }
        envelope["hash"] = envelope_hash(self.head, envelope)
        self.head = str(envelope["hash"])
        self.records.append(envelope)
        return envelope

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        current = read_bytes_guarded(self.path, 8_000_000) if self.path.exists() else None
        if current != self.loaded_bytes:
            raise ValueError("trail changed since load; reload before saving")
        content = "".join(_canonical(envelope) + "\n" for envelope in self.records)
        if len(content.encode("utf-8")) > 8_000_000:
            raise ValueError("trail exceeds 8000000 bytes")
        safe_write_text(self.path, content, label="triage trail")
        self.loaded_bytes = content.encode("utf-8")

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {
            "raw_findings": 0,
            "assessments": 0,
            "confirmed": 0,
            "quarantined": 0,
        }
        for envelope in self.records:
            if envelope["kind"] == "raw_finding":
                tally["raw_findings"] += 1
            elif envelope["kind"] == "assessment":
                tally["assessments"] += 1
                if envelope["record"].get("confirmation") == "confirmed":
                    tally["confirmed"] += 1
            elif envelope["kind"] == "quarantined_assessment":
                tally["quarantined"] += 1
        return tally


def append_raw_finding(trail: Trail, finding: dict[str, Any]) -> dict[str, Any]:
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-f]{8,64}", fingerprint):
        raise ValueError("raw findings need a hex fingerprint")
    return trail.append("raw_finding", dict(finding))


def append_assessment(trail: Trail, assessment: dict[str, Any]) -> dict[str, Any]:
    normalized = check_assessment(assessment)
    reason = quarantine_reason(normalized)
    if reason is not None:
        return trail.append("quarantined_assessment", {**normalized, "quarantine_reason": reason})
    return trail.append("assessment", normalized)


def suggest_duplicate_groups(
    assessments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deterministic duplicate suggestions. Never merges: humans confirm."""
    buckets: dict[tuple[str, str], list[str]] = {}
    for item in assessments:
        if item.get("imported"):
            key = ("external", str(item.get("original_rule_id", "")))
        else:
            key = ("native", str(item.get("rule_id", "")))
        trigger = re.sub(r"\s+", " ", str(item.get("trigger", "")).strip().lower())
        buckets.setdefault((key[0], key[1], trigger), []).append(str(item.get("fingerprint")))
    return [
        {"members": sorted(members), "basis": f"same {kind} {rule or 'rule'} and trigger"}
        for (kind, rule, _trigger), members in sorted(buckets.items())
        if len(members) > 1
    ]


def verify_fix(
    *,
    fingerprint: str,
    rescan_findings: list[str],
    new_blocking: list[str],
    test_command: str,
    test_exit_code: int | None,
) -> dict[str, Any]:
    """A fix is verified only with a clean re-scan AND an attested passing test."""
    rescan_clean = fingerprint not in rescan_findings and not new_blocking
    test_passed = test_exit_code == 0 and bool(test_command)
    reasons: list[str] = []
    if not rescan_clean:
        reasons.append("original finding still present or new blocking findings appeared")
    if test_exit_code is None:
        reasons.append("no test evidence attested")
    elif test_exit_code != 0:
        reasons.append(f"attested test exited {test_exit_code}")
    return {
        "fingerprint": fingerprint,
        "rescan_clean": rescan_clean,
        "test_command": test_command,
        "test_exit_code": test_exit_code,
        "test_passed": test_passed,
        "verified": bool(rescan_clean and test_passed),
        "reasons": reasons or ["re-scan clean and attested test passed"],
    }
