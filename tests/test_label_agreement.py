"""Two-reviewer label agreement and provisional/confirmed scoring."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
LABELS = importlib.util.spec_from_file_location(
    "finding_labels", ROOT / "scripts" / "finding_labels.py"
)
if LABELS is None or LABELS.loader is None:
    raise RuntimeError("could not load finding labels module")
finding_labels = importlib.util.module_from_spec(LABELS)
sys.modules[LABELS.name] = finding_labels
LABELS.loader.exec_module(finding_labels)


def record(reviewer, label, fingerprint="a" * 16, status="provisional"):
    return {
        "corpus": "realworld",
        "package": "gin",
        "revision": "b" * 40,
        "fingerprint": fingerprint,
        "rule_id": "SP101",
        "label": label,
        "proof_level": "L0",
        "application_scope": True,
        "shipproof_version": "0.11.2",
        "reviewer": reviewer,
        "status": status,
    }


class AgreementTests(unittest.TestCase):
    def test_two_reviewers_may_label_the_same_finding(self):
        lines = [
            record("ann", "true_positive", fingerprint="a" * 16, status="confirmed"),
            record("bob", "true_positive", fingerprint="a" * 16, status="confirmed"),
            record("ann", "false_positive", fingerprint="b" * 16, status="confirmed"),
            record("bob", "false_positive", fingerprint="b" * 16, status="confirmed"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.jsonl"
            path.write_text(
                "\n".join(__import__("json").dumps(item) for item in lines),
                encoding="utf-8",
            )
            records = finding_labels.load_label_records(Path(directory))
        self.assertEqual(len(records), 4)
        summary = finding_labels.agreement_summary(records)
        self.assertEqual(summary["double_labeled"], 2)
        self.assertEqual(summary["kappa"], 1.0)

    def test_same_reviewer_cannot_label_twice(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "labels.jsonl"
            path.write_text(
                "\n".join(
                    [
                        __import__("json").dumps(record("ann", "true_positive")),
                        __import__("json").dumps(record("ann", "false_positive")),
                    ]
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate label key"):
                finding_labels.load_label_records(Path(directory))

    def test_kappa_is_none_without_double_labels(self):
        summary = finding_labels.agreement_summary([record("ann", "true_positive")])
        self.assertIsNone(summary["kappa"])
        self.assertEqual(summary["single_labeled"], 1)

    def test_disagreement_lowers_kappa(self):
        records = [
            record("ann", "true_positive", fingerprint="a" * 16, status="confirmed"),
            record("bob", "true_positive", fingerprint="a" * 16, status="confirmed"),
            record("ann", "true_positive", fingerprint="b" * 16, status="confirmed"),
            record("bob", "false_positive", fingerprint="b" * 16, status="confirmed"),
        ]
        summary = finding_labels.agreement_summary(records)
        self.assertEqual(summary["double_labeled"], 2)
        self.assertLess(summary["kappa"], 1.0)
        self.assertEqual(len(summary["disagreements"]), 1)

    def test_legacy_records_stay_provisional(self):
        legacy = record("ann", "true_positive")
        del legacy["reviewer"]
        del legacy["status"]
        validated = finding_labels.validate_label_record(legacy, origin="test:1")
        self.assertEqual(validated["reviewer"], "legacy-single")
        self.assertEqual(validated["status"], "provisional")


if __name__ == "__main__":
    unittest.main()
