"""Original precision fixtures plus real Git-index integration regressions."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GIT_BINARY = shutil.which("git")
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
import scan_repo  # noqa: E402


class PrecisionRegressionTests(unittest.TestCase):
    def test_each_precision_rule_has_meaningful_polarities(self):
        cases = json.loads((ROOT / "tests/precision_cases.json").read_text())["cases"]
        counts = Counter((case["rule_id"], case["kind"]) for case in cases)
        for rule_id in ("SP210", "SP220", "SP583", "SP597", "SP599"):
            for kind, minimum in (("positive", 3), ("negative", 5), ("adversarial", 2)):
                with self.subTest(rule_id=rule_id, kind=kind):
                    self.assertGreaterEqual(counts[(rule_id, kind)], minimum)

    def test_worker_text_in_a_statement_regex_is_not_code(self):
        source = (
            "import { Worker } from 'bullmq';\n"
            "if (ready) /new Worker('q', processor, { skipStalledCheck: true })/.test(text);\n"
        )
        self.assertEqual(scan_repo.js_precision_lines(Path("worker.ts"), source, None), [])

    def test_client_directive_can_follow_other_directives(self):
        source = (
            "'use strict';\n'use client';\n"
            "export default async function Page() {\n"
            "const a = await fetch('https://a.invalid');\n"
            "const b = await fetch('https://b.invalid');\nreturn null;\n}"
        )
        self.assertEqual(
            scan_repo.js_precision_lines(Path("page.tsx"), source, frozenset({"nextjs"})), []
        )

    def test_many_imports_do_not_repeat_binding_analysis(self):
        source = "\n".join(f"import {{ Worker as W{i} }} from 'bullmq';" for i in range(600))
        source += "\nnew W599('q', processor, { skipStalledCheck: true });\n"
        with patch.object(
            scan_repo, "js_shadowed_bindings", wraps=scan_repo.js_shadowed_bindings
        ) as analyze:
            findings = scan_repo.js_precision_lines(Path("worker.ts"), source, None)
        self.assertEqual(analyze.call_count, 1)
        self.assertEqual(findings, [("SP583", 601)])

    def test_ambiguous_templates_and_token_budget_do_not_become_evidence(self):
        source = "const template = `text ${unknown}`;"
        self.assertEqual(scan_repo.js_context_tokens(source), [])
        self.assertEqual(scan_repo.js_context_tokens("value;" * 26_000), [])

    def test_curated_context_boundaries(self):
        cases = json.loads((ROOT / "tests/precision_cases.json").read_text())["cases"]
        for case in cases:
            with self.subTest(rule=case["rule_id"], name=case["name"]):
                if case["rule_id"] == "SP220":
                    findings = scan_repo.find_tracked_env_issues(
                        {case["path"]}, {case["path"]} if case["tracked_in_git"] else set()
                    )
                else:
                    findings = scan_repo.find_regex_issues(
                        Path(case["path"]),
                        case["path"],
                        bytes.fromhex(case["source_hex"]).decode(),
                        detected_frameworks=(
                            frozenset(case["frameworks"]) if "frameworks" in case else None
                        ),
                    )
                matches = [f for f in findings if f.rule_id == case["rule_id"]]
                self.assertEqual(len(matches), 1 if case["kind"] == "positive" else 0)


@unittest.skipUnless(GIT_BINARY, "Git is needed for real index evidence")
class TrackedEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git("init", "-q")
        (self.root / ".gitignore").write_text(".env\n.env.production\n", encoding="utf-8")
        (self.root / ".env").write_text("MODE=test\n", encoding="utf-8")
        (self.root / ".env.production").write_text("MODE=production\n", encoding="utf-8")
        (self.root / "safe.py").write_text("answer = 42\n", encoding="utf-8")

    def git(self, *args):
        return subprocess.run(  # noqa: S603 - test-owned arguments and temporary repository
            [GIT_BINARY, "-C", str(self.root), *args], check=True, capture_output=True
        )

    def env_findings(self, **kwargs):
        findings, stats = scan_repo.scan_repository(self.root, **kwargs)
        return [f for f in findings if f.rule_id == "SP220"], stats

    def test_untracked_env_and_ignore_text_do_not_prove_tracking(self):
        matches, _ = self.env_findings()
        self.assertEqual(matches, [])

    def test_real_index_and_scope_filters(self):
        self.git("add", "-f", "--", ".env", ".env.production")
        matches, _ = self.env_findings()
        self.assertEqual({f.path for f in matches}, {".env", ".env.production"})
        self.assertTrue(all(f.detection == "artifact" for f in matches))
        self.assertTrue(all("MODE=" not in f.evidence for f in matches))
        self.assertEqual(self.env_findings(include_paths=frozenset({"safe.py"}))[0], [])
        self.assertEqual(self.env_findings(exclude_patterns=(".env*",))[0], [])
        self.assertEqual(
            self.env_findings(excluded_paths=frozenset({".env", ".env.production"}))[0], []
        )

    def test_nested_scan_root_uses_relative_index_paths(self):
        nested = self.root / "sub space"
        nested.mkdir()
        (nested / ".env").write_text("MODE=test\n", encoding="utf-8")
        self.git("add", "-f", "--", "sub space/.env")
        findings, _ = scan_repo.scan_repository(nested)
        self.assertEqual([f.path for f in findings if f.rule_id == "SP220"], [".env"])

    def test_unavailable_index_does_not_become_a_clean_pass(self):
        with patch.object(scan_repo, "_run_git_bounded", side_effect=ValueError("unavailable")):
            matches, stats = self.env_findings()
        self.assertEqual(matches, [])
        self.assertFalse(stats["completeness"]["is_complete"])
        self.assertIn("git_index_unavailable", stats["completeness"]["reasons"])

    def test_missing_index_is_not_queried_without_selected_env_files(self):
        with patch.object(
            scan_repo, "_run_git_bounded", side_effect=AssertionError("unexpected Git")
        ):
            matches, stats = self.env_findings(include_paths=frozenset({"safe.py"}))
        self.assertEqual(matches, [])
        self.assertTrue(stats["completeness"]["is_complete"])

    def test_caller_git_directory_cannot_redirect_index_evidence(self):
        self.git("add", "-f", "--", ".env")
        with patch.dict(
            "os.environ",
            {
                "GIT_DIR": str(self.root / "missing"),
                "GIT_INDEX_FILE": str(self.root / "wrong-index"),
            },
        ):
            matches, stats = self.env_findings()
        self.assertEqual([finding.path for finding in matches], [".env"])
        self.assertTrue(stats["completeness"]["is_complete"])


if __name__ == "__main__":
    unittest.main()
