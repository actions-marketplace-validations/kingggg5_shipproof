#!/usr/bin/env python3
"""Load and score reviewed finding labels without treating unlabeled rows as truth."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ALLOWED_LABELS = frozenset({"true_positive", "false_positive", "needs_context", "duplicate"})
CORPUS_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
PACKAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
RULE_ID = re.compile(r"^SP[0-9]{3}$")
FINGERPRINT = re.compile(r"^[0-9a-f]{8,64}$")
REVIEWER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
LABEL_STATUSES = frozenset({"provisional", "confirmed"})
# Records written before the two-reviewer protocol carry no reviewer; they stay
# provisional forever and can never become confirmed without re-review.
LEGACY_REVIEWER = "legacy-single"


def load_label_records(directory: Path) -> list[dict[str, Any]]:
    if not directory.is_dir():
        return []
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for path in sorted(directory.glob("*.jsonl")):
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not raw.strip() or raw.lstrip().startswith("#"):
                continue
            try:
                item = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{line_number}: invalid JSON") from exc
            record = validate_label_record(item, origin=f"{path.name}:{line_number}")
            key = (
                record["corpus"],
                record["package"],
                record["revision"],
                record["fingerprint"],
                record["reviewer"],
            )
            if key in seen:
                raise ValueError(f"{path.name}:{line_number}: duplicate label key {key}")
            seen.add(key)
            records.append(record)
    return records


def validate_label_record(item: object, *, origin: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"{origin}: label records must be objects")
    required = (
        "corpus",
        "package",
        "revision",
        "fingerprint",
        "rule_id",
        "label",
        "proof_level",
        "application_scope",
        "shipproof_version",
    )
    missing = [field for field in required if field not in item]
    if missing:
        raise ValueError(f"{origin}: missing fields {missing}")
    corpus = item["corpus"]
    package = item["package"]
    fingerprint = item["fingerprint"]
    rule_id = item["rule_id"]
    label = item["label"]
    if not isinstance(corpus, str) or not CORPUS_NAME.fullmatch(corpus):
        raise ValueError(f"{origin}: invalid corpus name")
    if not isinstance(package, str) or not PACKAGE_NAME.fullmatch(package):
        raise ValueError(f"{origin}: invalid package name")
    if not isinstance(item["revision"], str) or not item["revision"]:
        raise ValueError(f"{origin}: revision is required")
    if not isinstance(fingerprint, str) or not FINGERPRINT.fullmatch(fingerprint):
        raise ValueError(f"{origin}: fingerprint must be lowercase hex")
    if not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id):
        raise ValueError(f"{origin}: invalid rule_id")
    if label not in ALLOWED_LABELS:
        raise ValueError(f"{origin}: label must be one of {sorted(ALLOWED_LABELS)}")
    if item["proof_level"] not in {"L0", "L1", "L2"}:
        raise ValueError(f"{origin}: invalid proof_level")
    if not isinstance(item["application_scope"], bool):
        raise ValueError(f"{origin}: application_scope must be a boolean")
    if not isinstance(item["shipproof_version"], str) or not item["shipproof_version"]:
        raise ValueError(f"{origin}: shipproof_version is required")
    reviewer = item.get("reviewer", LEGACY_REVIEWER)
    if not isinstance(reviewer, str) or not REVIEWER.fullmatch(reviewer):
        raise ValueError(f"{origin}: invalid reviewer")
    item["reviewer"] = reviewer
    status = item.get("status", "provisional")
    if status not in LABEL_STATUSES:
        raise ValueError(f"{origin}: status must be one of {sorted(LABEL_STATUSES)}")
    item["status"] = status
    notes = item.get("notes", "")
    if notes is not None and (not isinstance(notes, str) or len(notes) > 500):
        raise ValueError(f"{origin}: notes must be a string of at most 500 characters")
    return item


def index_labels(
    records: list[dict[str, Any]],
) -> dict[tuple[str, str, str, str], dict[str, Any]]:
    """Map each finding to one record. Confirmed beats provisional; ties break by reviewer.

    Two reviewers labeling the same finding is expected input, not a conflict:
    see agreement_summary for the inter-reviewer report.
    """
    ranked = sorted(
        records,
        key=lambda item: (
            item.get("status", "provisional") != "confirmed",
            str(item.get("reviewer", LEGACY_REVIEWER)),
        ),
    )
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in ranked:
        key = (item["corpus"], item["package"], item["revision"], item["fingerprint"])
        merged.setdefault(key, item)
    return merged


def agreement_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Cohen's kappa over findings labeled by at least two reviewers.

    Single-reviewer findings are counted but excluded from kappa: one opinion
    is not agreement evidence.
    """
    by_finding: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for item in records:
        key = (item["corpus"], item["package"], item["revision"], item["fingerprint"])
        reviewer = str(item.get("reviewer", LEGACY_REVIEWER))
        by_finding.setdefault(key, {})[reviewer] = item["label"]
    pairs = [votes for votes in by_finding.values() if len(votes) >= 2]
    reviewers = sorted({reviewer for votes in pairs for reviewer in votes})
    if len(reviewers) < 2 or not pairs:
        return {
            "reviewers": reviewers,
            "double_labeled": len(pairs),
            "single_labeled": len(by_finding) - len(pairs),
            "kappa": None,
            "note": "kappa needs findings labeled by at least two reviewers",
        }
    first, second = reviewers[0], reviewers[1]
    joint = [(votes[first], votes[second]) for votes in pairs if first in votes and second in votes]
    if not joint:
        return {
            "reviewers": reviewers,
            "double_labeled": len(pairs),
            "single_labeled": len(by_finding) - len(pairs),
            "kappa": None,
            "note": "the two reviewers share no labeled findings",
        }
    categories = sorted(ALLOWED_LABELS)
    observed = sum(1 for left, right in joint if left == right) / len(joint)
    left_counts = Counter(left for left, _ in joint)
    right_counts = Counter(right for _, right in joint)
    expected = sum(
        (left_counts[category] / len(joint)) * (right_counts[category] / len(joint))
        for category in categories
    )
    kappa = (observed - expected) / (1 - expected) if expected < 1 else None
    disagreements = [{"label_a": left, "label_b": right} for left, right in joint if left != right]
    return {
        "reviewers": [first, second],
        "double_labeled": len(joint),
        "single_labeled": len(by_finding) - len(pairs),
        "observed_agreement": round(observed, 4),
        "kappa": round(kappa, 4) if kappa is not None else None,
        "disagreements": disagreements[:50],
    }


def score_findings(
    findings: list[dict[str, Any]],
    labels: dict[tuple[str, str, str, str], dict[str, Any]],
    *,
    corpus: str,
    package: str,
    revision: str,
) -> dict[str, Any]:
    by_rule: dict[str, Counter[str]] = defaultdict(Counter)
    by_severity: dict[str, Counter[str]] = defaultdict(Counter)
    by_proof: dict[str, Counter[str]] = defaultdict(Counter)
    by_status: Counter[str] = Counter()
    unlabeled = 0
    for finding in findings:
        fingerprint = str(finding.get("fingerprint") or "")
        key = (corpus, package, revision, fingerprint)
        record = labels.get(key)
        if record is None:
            unlabeled += 1
            continue
        label = record["label"]
        by_status[str(record.get("status", "provisional"))] += 1
        rule_id = str(finding.get("rule_id") or record["rule_id"])
        severity = str(finding.get("severity") or "unknown")
        proof = str(finding.get("proof_level") or record["proof_level"])
        by_rule[rule_id][label] += 1
        by_severity[severity][label] += 1
        by_proof[proof][label] += 1
    return {
        "unreviewed": unlabeled,
        "reviewed_confirmed": by_status["confirmed"],
        "reviewed_provisional": by_status["provisional"],
        "by_rule": _matrix(by_rule),
        "by_severity": _matrix(by_severity),
        "by_proof_level": _matrix(by_proof),
    }


def _matrix(counts: dict[str, Counter[str]]) -> dict[str, dict[str, Any]]:
    payload: dict[str, dict[str, Any]] = {}
    for key, counter in sorted(counts.items()):
        true_positive = counter["true_positive"]
        false_positive = counter["false_positive"]
        reviewed = true_positive + false_positive
        precision = (true_positive / reviewed) if reviewed else None
        payload[key] = {
            "true_positive": true_positive,
            "false_positive": false_positive,
            "needs_context": counter["needs_context"],
            "duplicate": counter["duplicate"],
            "reviewed": reviewed,
            "precision": precision,
        }
    return payload


def fp_budget_violations(
    by_rule: dict[str, dict[str, Any]],
    *,
    high_critical_rule_ids: set[str] | None = None,
) -> list[str]:
    """High/critical rules with at least two false positives and no true positive."""
    violated = []
    for rule_id, stats in by_rule.items():
        if high_critical_rule_ids is not None and rule_id not in high_critical_rule_ids:
            continue
        if stats["false_positive"] >= 2 and stats["true_positive"] == 0:
            violated.append(rule_id)
    return sorted(violated)
