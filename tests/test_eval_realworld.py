from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "eval-realworld.py"
SPEC = importlib.util.spec_from_file_location("eval_realworld", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load real-world evaluation harness")
eval_realworld = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = eval_realworld
SPEC.loader.exec_module(eval_realworld)


class RealWorldManifestTests(unittest.TestCase):
    def test_git_runner_is_noninteractive_isolated_and_bounded(self):
        completed = eval_realworld.subprocess.CompletedProcess(["git", "version"], 0, "ok", "")
        injected = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "filter.evil.smudge",
            "GIT_CONFIG_VALUE_0": "dangerous-helper",
            "GIT_TEMPLATE_DIR": "unsafe-template",
            "git_config_key_1": "core.hooksPath",
            "git_template_dir": "unsafe-lowercase-template",
        }
        with (
            patch.object(eval_realworld.os, "environ", injected),
            patch.object(eval_realworld.subprocess, "run", return_value=completed) as run,
        ):
            self.assertIs(eval_realworld.run_git("version"), completed)
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], eval_realworld.os.devnull)
        self.assertFalse(
            any(
                key.upper().startswith("GIT_CONFIG_")
                and key.upper()
                not in {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_GLOBAL"}
                for key in environment
            )
        )
        self.assertFalse(any(key.lower() == "git_template_dir" for key in environment))
        self.assertEqual(run.call_args.kwargs["timeout"], eval_realworld.GIT_TIMEOUT_SECONDS)

    def test_prepare_uses_a_fresh_empty_git_template(self):
        revision = "a" * 40
        specification = {
            "name": "sample",
            "url": "https://github.com/example/sample.git",
            "revision": revision,
            "license_path": "LICENSE",
        }
        observed_template = None

        def fake_run_git(*arguments, cwd=None):
            nonlocal observed_template
            if arguments[0] == "init":
                template_argument = next(
                    value for value in arguments if value.startswith("--template=")
                )
                observed_template = Path(template_argument.removeprefix("--template="))
                self.assertTrue(observed_template.is_dir())
                self.assertEqual(list(observed_template.iterdir()), [])
                target = Path(arguments[-1])
                target.mkdir(parents=True)
                (target / "LICENSE").write_text("fixture license\n", encoding="utf-8")
            stdout = f"{revision}\n" if "rev-parse" in arguments else ""
            return eval_realworld.subprocess.CompletedProcess(arguments, 0, stdout, "")

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            with patch.object(eval_realworld, "run_git", side_effect=fake_run_git):
                target = eval_realworld.prepare(specification, workspace)
            self.assertEqual(target.resolve(), (workspace / "sample").resolve())
            self.assertIsNotNone(observed_template)
            self.assertFalse(observed_template.exists())

    def test_git_timeout_becomes_bounded_unavailable_evidence(self):
        with patch.object(
            eval_realworld.subprocess,
            "run",
            side_effect=eval_realworld.subprocess.TimeoutExpired(["git", "fetch"], 180),
        ):
            completed = eval_realworld.run_git("fetch")
        self.assertEqual(completed.returncode, 124)
        self.assertIn("timed out", completed.stderr)

    def test_checked_in_manifest_is_revision_and_license_pinned(self):
        path = ROOT / "benchmarks" / "realworld-repositories.json"
        manifest = eval_realworld.load_manifest(path)
        self.assertEqual(len(manifest["repositories"]), 10)
        self.assertEqual(
            {item["classification"] for item in manifest["repositories"]},
            {"clean_baseline", "intentionally_vulnerable"},
        )
        ecosystems = {item["ecosystem"] for item in manifest["repositories"]}
        self.assertGreaterEqual(len(ecosystems), 5)
        splits = {item["split"] for item in manifest["repositories"]}
        self.assertEqual(splits, {"development", "holdout"})
        by_name = {item["name"]: item for item in manifest["repositories"]}
        self.assertEqual(by_name["preact"]["split"], "holdout")
        self.assertEqual(by_name["gin"]["ecosystem"], "go")

    def test_manifest_rejects_moving_revisions_and_path_escape(self):
        payload = {
            "schema_version": 1,
            "repositories": [
                {
                    "name": "sample",
                    "url": "https://github.com/example/sample.git",
                    "revision": "main",
                    "classification": "clean_baseline",
                    "license_spdx": "MIT",
                    "license_path": "../LICENSE",
                    "license_url": "https://github.com/example/sample/blob/main/LICENSE",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "full lowercase commit"):
                eval_realworld.load_manifest(path)

    def test_manifest_rejects_license_permalink_for_another_repository(self):
        revision = "a" * 40
        payload = {
            "schema_version": 1,
            "repositories": [
                {
                    "name": "sample",
                    "url": "https://github.com/example/sample.git",
                    "revision": revision,
                    "classification": "clean_baseline",
                    "license_spdx": "MIT",
                    "license_path": "LICENSE",
                    "license_url": (f"https://github.com/attacker/other/blob/{revision}/LICENSE"),
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "same repository"):
                eval_realworld.load_manifest(path)

    def test_empty_only_selection_is_invalid_evidence(self):
        original_argv = sys.argv
        sys.argv = [str(SCRIPT), "--only", ","]
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(eval_realworld.main(), 2)
        finally:
            sys.argv = original_argv

    def test_tree_digest_ignores_git_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("value = 1\n", encoding="utf-8")
            first = eval_realworld.sha256_tree(root)
            (root / ".git").mkdir()
            (root / ".git" / "HEAD").write_text("moving", encoding="utf-8")
            self.assertEqual(first, eval_realworld.sha256_tree(root))

    def test_manifest_rejects_unknown_split_and_kind(self):
        revision = "a" * 40
        payload = {
            "schema_version": 1,
            "repositories": [
                {
                    "name": "sample",
                    "url": "https://github.com/example/sample.git",
                    "revision": revision,
                    "classification": "clean_baseline",
                    "ecosystem": "python",
                    "kind": "spaceship",
                    "split": "development",
                    "license_spdx": "MIT",
                    "license_path": "LICENSE",
                    "license_url": f"https://github.com/example/sample/blob/{revision}/LICENSE",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manifest.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "kind must be one of"):
                eval_realworld.load_manifest(path)

    def test_ground_truth_recall_is_unknown_without_independent_defects(self):
        report = eval_realworld.recall_report(None, [])
        self.assertEqual(report["status"], "unknown")

    def test_ground_truth_recall_matches_path_within_line_window(self):
        ground_truth = {
            "schema_version": 1,
            "repo": "demo",
            "revision": "b" * 40,
            "defects": [
                {
                    "id": "GHSA-1",
                    "path": "app.py",
                    "line": 10,
                    "cwe": "CWE-89",
                    "reference": "https://example.test/advisory",
                },
                {
                    "id": "GHSA-2",
                    "path": "other.py",
                    "line": 3,
                    "cwe": "CWE-78",
                    "reference": "https://example.test/advisory-2",
                },
            ],
        }
        findings = [
            type("Finding", (), {"path": "app.py", "line": 12})(),
            type("Finding", (), {"path": "unrelated.py", "line": 3})(),
        ]
        report = eval_realworld.recall_report(ground_truth, findings)
        self.assertEqual(report["status"], "measured")
        self.assertEqual(report["defects"], 2)
        self.assertEqual(report["recalled"], 1)
        self.assertEqual(report["missed_ids"], ["GHSA-2"])


if __name__ == "__main__":
    unittest.main()
