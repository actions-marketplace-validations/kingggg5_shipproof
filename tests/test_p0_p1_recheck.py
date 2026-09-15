"""Regression contracts for scoped coverage and reviewed suppression boundaries."""

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills/audit-production-readiness/scripts"))
import scan_repo  # noqa: E402


class RecheckTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()

    def put(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return target

    def run_cli(self, *arguments):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = scan_repo.main([str(self.root), *arguments])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_changed_scope_does_not_count_omissions_outside_selection(self):
        self.put("app.py", "value = 1\n")
        self.put("unrelated.zip", "container")
        self.put("old.py", "x" * 100)
        _, stats = scan_repo.scan_repository(
            self.root, max_file_bytes=50, include_paths=frozenset({"app.py"})
        )
        self.assertTrue(stats["completeness"]["is_complete"])
        self.assertEqual(stats["files_scanned"], 1)

    def test_explicit_excludes_apply_to_containers(self):
        self.put("unrelated.zip", "container")
        _, stats = scan_repo.scan_repository(self.root, exclude_patterns=("*.zip",))
        self.assertTrue(stats["completeness"]["is_complete"])
        self.assertEqual(stats["completeness"]["excluded"], 1)

    def test_tracked_file_inside_ignored_tree_is_not_silently_skipped(self):
        self.put("node_modules/implanted.py", "result = " + "ev" + "al(user_input)\n")
        (self.root / ".git").mkdir()
        with mock.patch.object(
            scan_repo,
            "_tracked_paths_for_scan",
            return_value=frozenset({"node_modules/implanted.py"}),
        ):
            findings, stats = scan_repo.scan_repository(self.root)
        self.assertTrue(any(item.path == "node_modules/implanted.py" for item in findings))
        self.assertEqual(stats["files_scanned"], 1)
        self.assertTrue(stats["completeness"]["is_complete"])

    def test_git_path_symlink_parent_is_rejected(self):
        outside_context = tempfile.TemporaryDirectory()
        self.addCleanup(outside_context.cleanup)
        outside = Path(outside_context.name)
        git_name = "git.exe" if os.name == "nt" else "git"
        (outside / git_name).write_text("not a real executable", encoding="utf-8")
        linked = self.root / "tool-bin"
        try:
            linked.symlink_to(outside, target_is_directory=True)
        except OSError as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        with (
            mock.patch.object(scan_repo.shutil, "which", return_value=str(linked / git_name)),
            self.assertRaisesRegex(ValueError, "refused a Git executable"),
        ):
            scan_repo._trusted_git_binary(self.root)

    def test_explicit_selection_can_enter_ignored_tree_without_git(self):
        self.put("dist/implanted.py", "result = " + "ev" + "al(user_input)\n")
        findings, stats = scan_repo.scan_repository(
            self.root, include_paths=frozenset({"dist/implanted.py"})
        )
        self.assertTrue(any(item.path == "dist/implanted.py" for item in findings))
        self.assertEqual(stats["files_scanned"], 1)
        self.assertTrue(stats["completeness"]["is_complete"])

    def test_selected_baseline_exclusion_precedes_size_classification(self):
        self.put("baseline.json", "x" * 100)
        _, stats = scan_repo.scan_repository(
            self.root, max_file_bytes=50, excluded_paths=frozenset({"baseline.json"})
        )
        self.assertTrue(stats["completeness"]["is_complete"])
        self.assertEqual(stats["completeness"]["baseline_excluded"], 1)

    def test_unreadable_directory_is_not_a_complete_scan(self):
        def failed_walk(root, *, topdown, onerror, **kwargs):
            onerror(PermissionError(13, "denied", str(self.root / "private")))
            return iter(())

        with mock.patch.object(scan_repo.os, "walk", side_effect=failed_walk):
            _, stats = scan_repo.scan_repository(self.root)
        self.assertFalse(stats["completeness"]["is_complete"])
        self.assertEqual(stats["completeness"]["unreadable"], 1)

    def test_file_growth_after_discovery_cannot_bypass_read_limit(self):
        self.put("app.py", "x" * 100)
        with mock.patch.object(
            scan_repo,
            "iter_scannable_files",
            return_value=iter([(self.root / "app.py", "app.py", None)]),
        ):
            _, stats = scan_repo.scan_repository(self.root, max_file_bytes=50)
        self.assertFalse(stats["completeness"]["is_complete"])
        self.assertEqual(stats["completeness"]["oversized"], 1)
        self.assertEqual(stats["files_scanned"], 0)

    def test_unreadable_directory_outside_changed_scope_does_not_fail_coverage(self):
        def failed_walk(root, *, topdown, onerror, **kwargs):
            onerror(PermissionError(13, "denied", str(self.root / "private")))
            return iter(())

        with mock.patch.object(scan_repo.os, "walk", side_effect=failed_walk):
            _, stats = scan_repo.scan_repository(self.root, include_paths=frozenset({"app.py"}))
        self.assertTrue(stats["completeness"]["is_complete"])

    def test_invalid_utf8_is_an_omission_not_a_successfully_scanned_file(self):
        (self.root / "invalid.py").write_bytes(b"value = 1\n\xff")
        _, stats = scan_repo.scan_repository(self.root)
        self.assertEqual(stats["files_scanned"], 0)
        self.assertEqual(stats["completeness"]["unreadable"], 1)

    def test_parallel_fallback_does_not_double_count_omissions(self):
        self.put("app.py", "value = 1\n")
        (self.root / "invalid.py").write_bytes(b"\xff")

        def partially_failed_map(function, tasks, **kwargs):
            for task in tasks:
                yield function(task)
            raise RuntimeError("worker failed after partial results")

        with (
            mock.patch("concurrent.futures.ProcessPoolExecutor") as pool,
            mock.patch.object(scan_repo, "PARALLEL_MIN_FILES", 1),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            pool.return_value.__enter__.return_value.map.side_effect = partially_failed_map
            _, stats = scan_repo.scan_repository(self.root, jobs=2)
        self.assertEqual(stats["files_scanned"], 1)
        self.assertEqual(stats["completeness"]["unreadable"], 1)

    def test_database_inspection_reads_only_a_bounded_header(self):
        self.put("data.sqlite", "SQLite format 3\0" + "x" * 500)
        with mock.patch.object(
            scan_repo, "read_scannable_bytes", wraps=scan_repo.read_scannable_bytes
        ) as reader:
            findings, stats = scan_repo.scan_repository(self.root, max_file_bytes=50)
        reader.assert_called_once_with(self.root / "data.sqlite", 16, header_only=True)
        self.assertTrue(any(item.rule_id == "SP314" for item in findings))
        self.assertTrue(stats["completeness"]["is_complete"])

    def test_manifest_discovery_honors_read_limit_and_ignores_invalid_shape(self):
        self.put("package.json", "[]")
        self.assertEqual(scan_repo.detect_frameworks(self.root), set())
        self.put("package.json", json.dumps({"dependencies": {"react": "1.0.0"}}) + " " * 200)
        with mock.patch.object(
            scan_repo, "read_scannable_bytes", wraps=scan_repo.read_scannable_bytes
        ) as reader:
            self.assertEqual(scan_repo.detect_frameworks(self.root, 50), set())
        reader.assert_called_once_with(self.root / "package.json", 50)

    def test_reparse_directory_is_pruned_in_scan_and_skill_discovery(self):
        self.put("alias/SKILL.md", "# External descriptor\n")
        original_lstat = os.lstat

        def directory_reparse(path, *args, **kwargs):
            if Path(path) == self.root / "alias":
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original_lstat(path, *args, **kwargs)

        with mock.patch.object(os, "lstat", side_effect=directory_reparse):
            self.assertEqual(scan_repo.discover_skill_roots(self.root, ()), frozenset())
            for scope in (None, frozenset({"alias"}), frozenset({"alias/SKILL.md"})):
                with self.subTest(scope=scope):
                    _, stats = scan_repo.scan_repository(self.root, include_paths=scope)
                    self.assertEqual(stats["files_scanned"], 0)
                    self.assertEqual(stats["completeness"]["symlinks"], 1)

    def test_nonregular_source_is_never_opened(self):
        self.put("pipe.py", "not a real FIFO in this fixture")
        original_lstat = os.lstat

        def nonregular_stat(path, *args, **kwargs):
            if Path(path) == self.root / "pipe.py":
                return SimpleNamespace(st_mode=stat.S_IFIFO, st_file_attributes=0)
            return original_lstat(path, *args, **kwargs)

        with (
            mock.patch.object(os, "lstat", side_effect=nonregular_stat),
            mock.patch.object(scan_repo, "read_scannable_bytes") as reader,
        ):
            _, stats = scan_repo.scan_repository(self.root)
        reader.assert_not_called()
        self.assertEqual(stats["files_scanned"], 0)
        self.assertEqual(stats["completeness"]["unreadable"], 1)

    def test_baseline_output_has_a_review_required_default_reason(self):
        self.put("app.py", "result = " + "ev" + "al(value)\n")
        generated = self.root / "baseline.json"
        status, _, stderr = self.run_cli("--baseline-out", str(generated), "--fail-on", "none")
        self.assertEqual(status, 0, stderr)
        baseline = scan_repo.load_baseline_fingerprints(generated)
        self.assertTrue(baseline.fingerprints)
        self.assertEqual(
            set(baseline.fingerprints.values()), {"Generated baseline; review required"}
        )

    def test_baseline_output_limits_do_not_replace_an_existing_file(self):
        self.put("app.py", "result = " + "ev" + "al(value)\n")
        generated = self.put("baseline.json", "previous contents")
        with mock.patch.object(scan_repo, "MAX_BASELINE_FINGERPRINTS", 0):
            status, _, _ = self.run_cli("--baseline-out", str(generated))
        self.assertEqual(status, 2)
        self.assertEqual(generated.read_text(encoding="utf-8"), "previous contents")

    def test_report_writer_rejects_final_and_parent_symlinks(self):
        outside = Path(self.tmp.name).parent / f"{Path(self.tmp.name).name}-outside"
        outside.mkdir()
        self.addCleanup(lambda: outside.exists() and os.rmdir(outside))
        try:
            final_link = self.root / "report.md"
            os.symlink(outside / "owned.md", final_link)
            parent_link = self.root / "reports"
            os.symlink(outside, parent_link, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable")
        with self.assertRaises(ValueError):
            scan_repo.safe_write_text(final_link, "attacker-controlled report")
        with self.assertRaises(ValueError):
            scan_repo.safe_write_text(parent_link / "report.md", "attacker-controlled report")
        self.assertFalse((outside / "owned.md").exists())

    def test_parser_limit_is_incomplete_evidence(self):
        self.put("broken.py", "def route(:\n    return eval(value)\n")
        _, stats = scan_repo.scan_repository(self.root)
        self.assertEqual(stats["files_scanned"], 0)
        self.assertEqual(stats["completeness"]["parser_limit"], 1)
        self.assertEqual(stats["completeness"]["reasons"], ["parser_limit"])

    def test_invalid_python_snippet_is_unavailable_evidence(self):
        status, _output, stderr = self.run_cli(
            "--snippet",
            "def route(:\n    return eval(value)\n",
            "--snippet-file",
            "snippet.py",
        )
        self.assertEqual(status, 2)
        self.assertIn("parser_limit", stderr)

    def test_overlong_snippet_is_invalid_evidence_not_a_regex_timeout(self):
        source = "SELECT * FROM " + ("a" * (scan_repo.MAX_SCAN_LINE_CHARS + 1))
        status, _output, stderr = self.run_cli(
            "--snippet",
            source,
            "--snippet-file",
            "query.sql",
        )
        self.assertEqual(status, 2)
        self.assertIn("line_limit", stderr)

    def test_direct_regex_helper_rejects_overlong_line(self):
        source = "SELECT * FROM " + ("a" * (scan_repo.MAX_SCAN_LINE_CHARS + 1))
        with self.assertRaisesRegex(scan_repo.ScanCoverageError, "line_limit"):
            scan_repo.find_regex_issues(Path("query.sql"), "query.sql", source)

    def test_finding_accumulator_has_a_hard_limit(self):
        source = ("value = ev" + "al(input)\n") * 3
        with (
            mock.patch.object(scan_repo, "MAX_FINDINGS_PER_FILE", 2),
            self.assertRaises(scan_repo.FindingLimitError),
        ):
            scan_repo.find_regex_issues(Path("app.py"), "app.py", source)

    def test_terminal_renderer_escapes_control_sequences(self):
        source = "value = ev" + "al(input)\x1b[2J\n"
        self.put("app.py", source)
        findings = scan_repo.find_regex_issues(Path("app.py"), "app.py", source)
        rendered = scan_repo.render_terminal_report(
            self.root,
            findings,
            {
                "files_scanned": 1,
                "suppressed": 0,
                "completeness": {"is_complete": True, "reasons": []},
            },
        )
        self.assertNotIn("\x1b", rendered)
        self.assertIn("\\x1b", rendered)

    def test_sarif_and_trace_preserve_incomplete_coverage(self):
        self.put("payload.zip", "container")
        status, output, _ = self.run_cli("--format", "sarif", "--fail-on-incomplete")
        self.assertEqual(status, 1)
        run = json.loads(output)["runs"][0]
        self.assertFalse(run["properties"]["completeness"]["is_complete"])
        self.assertFalse(run["invocations"][0]["executionSuccessful"])
        status, output, _ = self.run_cli("--format", "json", "--trace", "--fail-on-incomplete")
        report = json.loads(output)
        self.assertEqual(status, 1)
        self.assertEqual(report["verdict"], "CONDITIONAL")
        self.assertEqual(report["decision_trace"]["gate"]["verdict"], "CONDITIONAL")
        self.assertTrue(report["decision_trace"]["gate"]["failed"])

    def test_fix_dry_run_cannot_bypass_incomplete_gate(self):
        self.put("payload.zip", "container")
        status, _, _ = self.run_cli("--fix-dry-run", "--fail-on-incomplete")
        self.assertEqual(status, 1)

    def test_human_readable_verdict_respects_include_tests(self):
        self.put("tests/example.py", "api_" + "key = '" + "K7mQ2xR9" + "nP4wL8sT3vY1'\n")
        for format_name in ("markdown", "terminal"):
            with self.subTest(format=format_name):
                status, output, stderr = self.run_cli("--format", format_name, "--include-tests")
                self.assertEqual(status, 1, stderr)
                self.assertIn("BLOCK", output)
                self.assertNotIn("PASS_WITH_EVIDENCE", output)

    def test_show_suppressed_unsupported_output_is_rejected(self):
        for mode in (("--format", "github"), ("--fix-prompt",), ("--snippet", "x=1")):
            with self.subTest(mode=mode):
                status, _, _ = self.run_cli(*mode, "--show-suppressed")
                self.assertEqual(status, 2)

    def test_edge_runtime_rule_rejects_ordinary_node_and_noncode_signals(self):
        native_import = 'import fs from "node:fs";\n'
        negatives = [
            native_import + 'const runtime = "nodejs"; // completeness ledger\n',
            native_import + '// export const runtime = "edge";\n',
            native_import + '/*\nexport const runtime = "edge";\n*/\n',
            native_import + 'const example = `\nexport const runtime = "edge";\n`;\n',
            native_import + "const example = \"text\\\nexport const runtime = 'edge';\";\n",
            'export const runtime = "edge";\n// ' + native_import,
            'export const runtime = "edge";\nimport type { Stats } from "node:fs";\n',
            native_import + 'export const runtime = "edge" + "-compatible";\n',
        ]
        for source in negatives:
            with self.subTest(source=source):
                findings = scan_repo.find_regex_issues(Path("route.ts"), "route.ts", source)
                self.assertFalse(any(item.rule_id == "SP631" for item in findings))

    def test_baseline_explicit_null_matchers_cannot_widen_scope(self):
        for field in ("id", "path", "evidence"):
            baseline = self.put(
                "baseline.json",
                json.dumps(
                    {
                        "version": 2,
                        "rules": [
                            {"id": "SP101", "path": "tests/**", field: None, "reason": "reviewed"}
                        ],
                    }
                ),
            )
            with self.subTest(field=field), self.assertRaises(ValueError):
                scan_repo.load_baseline_fingerprints(baseline)

    def test_baseline_output_can_be_loaded_again_with_glob_rules(self):
        self.put("app.py", "value = 1\n")
        baseline = self.put(
            "baseline.json",
            json.dumps({"version": 2, "rules": [{"id": "SP101", "reason": "reviewed"}]}),
        )
        regenerated = self.root / "regenerated.json"
        status, _, stderr = self.run_cli(
            "--format", "json", "--baseline", str(baseline), "--baseline-out", str(regenerated)
        )
        self.assertEqual(status, 0, stderr)
        loaded = scan_repo.load_baseline_fingerprints(regenerated)
        self.assertEqual(loaded.rules[0].rule_id, "SP101")

    def test_misspelled_baseline_scope_fails_closed(self):
        baseline = self.put(
            "baseline.json",
            json.dumps(
                {
                    "version": 2,
                    "rules": [{"id": "SP101", "paths": "tests/**", "reason": "reviewed test only"}],
                }
            ),
        )
        with self.assertRaises(ValueError):
            scan_repo.load_baseline_fingerprints(baseline)

    def test_baseline_rejects_ambiguous_or_unbounded_metadata(self):
        payloads = [
            '{"version":2,"rules":[],"rules":[{"id":"*","reason":"ambiguous"}]}',
            json.dumps({"version": True, "fingerprints": []}),
            json.dumps({"version": 2, "rules": [{"id": "*", "reason": "x" * 513}]}),
            json.dumps({"version": 2, "rules": [{"id": "*", "reason": "unsafe\u001b[2J"}]}),
            json.dumps({"version": 2, "fingerprints": [{"hash": "abc", "reason": ""}]}),
        ]
        for payload in payloads:
            with self.subTest(payload=payload[:90]):
                baseline = self.put("baseline.json", payload)
                with self.assertRaises(ValueError):
                    scan_repo.load_baseline_fingerprints(baseline)

    def test_baseline_has_input_and_rule_count_limits(self):
        baseline = self.put("baseline.json", " " * 2_000_001)
        with self.assertRaisesRegex(ValueError, "limit"):
            scan_repo.load_baseline_fingerprints(baseline)
        baseline = self.put(
            "baseline.json",
            json.dumps({"version": 2, "rules": [{"id": "SP101", "reason": "reviewed"}] * 257}),
        )
        with self.assertRaisesRegex(ValueError, "limit"):
            scan_repo.load_baseline_fingerprints(baseline)

    def test_symlink_directory_is_accounted_without_following(self):
        target = self.root / "outside"
        target.mkdir()
        link = self.root / "alias"
        try:
            os.symlink(target, link, target_is_directory=True)
        except OSError:
            self.skipTest("directory symlinks unavailable")
        _, stats = scan_repo.scan_repository(self.root)
        self.assertEqual(stats["completeness"]["symlinks"], 1)


if __name__ == "__main__":
    unittest.main()
