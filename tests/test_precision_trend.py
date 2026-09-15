from __future__ import annotations

import importlib.util
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "check-precision-trend.py"
SPEC = importlib.util.spec_from_file_location("check_precision_trend", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load precision trend checker")
check_precision_trend = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_precision_trend
SPEC.loader.exec_module(check_precision_trend)


class PrecisionTrendTests(unittest.TestCase):
    def test_checked_in_baseline_meets_thresholds(self):
        report = check_precision_trend.load_json(ROOT / "benchmarks" / "clean-corpus-baseline.json")
        thresholds = check_precision_trend.load_json(
            ROOT / "benchmarks" / "precision-thresholds.json"
        )
        metrics = check_precision_trend.corpus_metrics(report)
        failures = check_precision_trend.check_clean_corpus(metrics, thresholds["clean_corpus"])
        self.assertEqual(failures, [])
        self.assertEqual(metrics["blocked_packages"], 0)
        self.assertEqual(metrics["high_critical_app_findings"], 0)
        self.assertLessEqual(metrics["gate_high_medium_findings"], 22)

    def test_blocked_package_fails_the_gate(self):
        payload = {
            "summary": {"blocked_count": 1},
            "packages": [
                {
                    "app_finding_records": [
                        {
                            "severity": "high",
                            "tier": "gate",
                            "confidence": "high",
                            "rule_id": "SP101",
                        }
                    ]
                }
            ],
            "label_report": {"fp_budget_violations": [], "unreviewed_high_critical": 1},
        }
        thresholds = {
            "max_blocked_packages": 0,
            "max_high_critical_app_findings": 0,
            "max_gate_high_medium_findings": 22,
            "max_high_confidence_ratio": 0.5,
            "max_fp_budget_violations": 0,
            "max_unreviewed_high_critical": 0,
        }
        metrics = check_precision_trend.corpus_metrics(payload)
        failures = check_precision_trend.check_clean_corpus(metrics, thresholds)
        self.assertTrue(any("blocked" in item for item in failures))
        self.assertTrue(any("high/critical" in item for item in failures))

    def test_script_exit_zero_on_checked_in_baseline(self):
        previous = sys.argv
        old_stdout = sys.stdout
        try:
            sys.argv = [
                "check-precision-trend.py",
                "--report",
                str(ROOT / "benchmarks" / "clean-corpus-baseline.json"),
                "--json",
            ]
            sys.stdout = io.StringIO()
            self.assertEqual(check_precision_trend.main(), 0)
        finally:
            sys.stdout = old_stdout
            sys.argv = previous


if __name__ == "__main__":
    unittest.main()
