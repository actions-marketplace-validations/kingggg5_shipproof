"""Q09 acceptance: every surface tells the same scope/verdict/completeness story."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan_repo  # noqa: E402
from scan_repo import (  # noqa: E402
    build_json_report,
    build_sarif_report,
    render_markdown_report,
    render_terminal_report,
)


class OutputConsistencyTests(unittest.TestCase):
    def scan_fixture(self, root: Path):
        (root / "app.py").write_text(
            "import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8"
        )
        return scan_repo.scan_repository(root)

    def test_all_surfaces_agree_on_verdict_counts_and_completeness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            findings, stats = self.scan_fixture(root)
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"])
            verdicts = set()
            counts: dict[str, int] = {}

            report = build_json_report(root, findings, stats)
            verdicts.add(report["verdict"])
            counts["json"] = len(report["findings"])
            self.assertIn("limitations", report)
            for finding in report["findings"]:
                self.assertIn("scope", finding)
                self.assertIn("proof_level", finding)

            sarif = build_sarif_report(findings, root, completeness=completeness)
            run = sarif["runs"][0]
            self.assertTrue(run["invocations"][0]["executionSuccessful"])
            self.assertTrue(run["properties"]["completeness"]["is_complete"])
            counts["sarif"] = len(run["results"])
            for result in run["results"]:
                self.assertIn("proof_level", result["properties"])

            terminal = render_terminal_report(root, findings, stats)
            markdown = render_markdown_report(root, findings, stats)
            for rendered in (terminal, markdown):
                self.assertIn(report["verdict"], rendered)
            self.assertNotIn("complete pass", terminal.lower() + markdown.lower())
            counts["terminal"] = terminal.count("SP151")
            self.assertEqual(counts["json"], counts["sarif"])
            self.assertGreaterEqual(counts["terminal"], 1)
            self.assertEqual(len(verdicts), 1)

    def test_incomplete_coverage_is_visible_everywhere(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "payload.zip").write_text("container", encoding="utf-8")
            findings, stats = scan_repo.scan_repository(root)
            completeness = stats["completeness"]
            self.assertFalse(completeness["is_complete"])
            report = build_json_report(root, findings, stats)
            self.assertEqual(report["verdict"], "CONDITIONAL")
            self.assertTrue(
                any("incomplete" in str(item).lower() for item in report["limitations"])
            )
            sarif = build_sarif_report(findings, root, completeness=completeness)
            run = sarif["runs"][0]
            self.assertFalse(run["properties"]["completeness"]["is_complete"])
            self.assertFalse(run["invocations"][0]["executionSuccessful"])
            terminal = render_terminal_report(root, findings, stats)
            self.assertIn("CONDITIONAL", terminal)


if __name__ == "__main__":
    unittest.main()
