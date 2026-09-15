"""Coverage ledger, suppression v2 baseline, and eval-dataset scope tests."""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import scan_repo  # noqa: E402
from scan_repo import (  # noqa: E402
    SuppressionBaseline,
    SuppressionRule,
    build_json_report,
    build_sarif_report,
    deduplicate_and_suppress_findings,
    determine_scope,
    determine_verdict,
    find_regex_issues,
    load_baseline_fingerprints,
    main,
    scan_repository,
)


def make_repo(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    for name, content in files.items():
        target = Path(tmp.name) / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp


class CoverageLedgerTests(unittest.TestCase):
    def test_clean_repo_is_complete(self):
        with make_repo({"app.py": "value = 1\n"}) as tmp:
            findings, stats = scan_repository(Path(tmp))
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], [])
            self.assertEqual(completeness["binary"], 0)
            self.assertEqual(
                determine_verdict(findings, completeness=completeness),
                "PASS_WITH_EVIDENCE",
            )

    def test_oversized_file_makes_scan_incomplete(self):
        with make_repo({"big.json": "x" * 40}) as tmp:
            findings, stats = scan_repository(Path(tmp), max_file_bytes=10)
            completeness = stats["completeness"]
            self.assertFalse(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], ["oversized"])
            self.assertEqual(completeness["oversized"], 1)
            report = build_json_report(Path(tmp), findings, stats)
            self.assertEqual(report["verdict"], "CONDITIONAL")
            self.assertTrue(
                any("incomplete" in item for item in report["limitations"]),
                report["limitations"],
            )

    def test_oversized_file_in_skip_tree_does_not_fail_completeness(self):
        with make_repo(
            {
                "app.py": "value = 1\n",
                "research/catalog.json": "x" * 40,
                "node_modules/pkg/big.json": "x" * 40,
            }
        ) as tmp:
            findings, stats = scan_repository(
                Path(tmp),
                max_file_bytes=20,
                include_paths=frozenset(
                    {"app.py", "research/catalog.json", "node_modules/pkg/big.json"}
                ),
            )
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], [])
            self.assertEqual(completeness["oversized"], 0)
            self.assertEqual(completeness["excluded"], 2)
            self.assertEqual(stats["files_scanned"], 1)
            self.assertEqual(findings, [])

    def test_overlong_line_makes_scan_incomplete_before_regex_matching(self):
        source = "SELECT * FROM " + ("a" * (scan_repo.MAX_SCAN_LINE_CHARS + 1))
        with make_repo({"query.sql": source}) as tmp:
            findings, stats = scan_repository(Path(tmp), max_file_bytes=200_000)
            completeness = stats["completeness"]
            self.assertFalse(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], ["line_limit"])
            self.assertEqual(completeness["line_limit"], 1)
            self.assertEqual(findings, [])
            self.assertEqual(stats["files_scanned"], 0)

    def test_container_file_makes_scan_incomplete(self):
        with make_repo({"payload.zip": "PK\x03\x04 not really a zip"}) as tmp:
            _, stats = scan_repository(Path(tmp))
            completeness = stats["completeness"]
            self.assertFalse(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], ["containers"])
            self.assertEqual(completeness["containers"], 1)

    def test_database_file_is_counted_but_still_reported(self):
        with make_repo({"data.sqlite": "x" * 64}) as tmp:
            findings, stats = scan_repository(Path(tmp))
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"])
            self.assertEqual(completeness["databases"], 1)
            self.assertTrue(any(item.rule_id == "SP314" for item in findings))

    def test_assets_and_excludes_never_trigger_incompleteness(self):
        with make_repo({"logo.png": "pixels", "vendored.py": "value = 1\n"}) as tmp:
            _, stats = scan_repository(Path(tmp), exclude_patterns=("vendored.py",))
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"])
            self.assertEqual(completeness["assets"], 1)
            self.assertEqual(completeness["excluded"], 1)

    def test_generated_sarif_report_is_asset_not_unknown_binary(self):
        snippet = 'AWS_SECRET_ACCESS_KEY = "' + "A" * 40 + '"\n'
        sarif = json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "results": [
                            {
                                "message": {"text": snippet},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "app.py"},
                                            "region": {
                                                "startLine": 1,
                                                "snippet": {"text": snippet},
                                            },
                                        }
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        )
        with make_repo({"app.py": "value = 1\n", "shipproof.sarif": sarif}) as tmp:
            findings, stats = scan_repository(Path(tmp))
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], [])
            self.assertEqual(completeness["assets"], 1)
            self.assertEqual(completeness["binary"], 0)
            self.assertEqual(findings, [])

    def test_unreadable_file_makes_scan_incomplete(self):
        with make_repo({"broken.py": "value = 1\n"}) as tmp:
            real_open = scan_repo.os.open

            def flaky_open(path, *args, **kwargs):
                if Path(path).name == "broken.py":
                    raise OSError("permission denied")
                return real_open(path, *args, **kwargs)

            with mock.patch.object(scan_repo.os, "open", flaky_open):
                _, stats = scan_repository(Path(tmp))
            self.assertFalse(stats["completeness"]["is_complete"])
            self.assertEqual(stats["completeness"]["reasons"], ["unreadable"])
            self.assertEqual(stats["files_scanned"], 0)

    def test_fail_on_incomplete_exit_contract(self):
        with (
            make_repo({"payload.zip": "PK\x03\x04 junk"}) as tmp,
            contextlib.redirect_stdout(io.StringIO()),
        ):
            blocked_by_default = main([tmp, "--format", "json", "--fail-on", "none"])
            exploratory = main([tmp, "--format", "json", "--fail-on", "none", "--allow-incomplete"])
            blocked = main([tmp, "--format", "json", "--fail-on", "none", "--fail-on-incomplete"])
        self.assertEqual(blocked_by_default, 1)
        self.assertEqual(exploratory, 0)
        self.assertEqual(blocked, 1)


class SuppressionBaselineV2Tests(unittest.TestCase):
    def findings(self, tmp_name: str, source: str, filename: str = "app.py"):
        candidates = find_regex_issues(Path(filename), filename, source)
        return candidates

    def test_version_one_string_baselines_still_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps({"version": 1, "fingerprints": ["abc", "def"]}), encoding="utf-8"
            )
            baseline = load_baseline_fingerprints(path)
            self.assertEqual(set(baseline.fingerprints), {"abc", "def"})
            self.assertEqual(baseline.rules, ())

    def test_v2_fingerprint_objects_carry_reasons(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "scanner_version": "0.8.0",
                        "rules": [],
                        "fingerprints": [
                            {
                                "hash": "abc123",
                                "rule_id": "SP101",
                                "path": "app.py",
                                "reason": "dev sandbox",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            baseline = load_baseline_fingerprints(path)
            self.assertEqual(baseline.fingerprints["abc123"], "dev sandbox")

    def test_rules_require_reason_and_matcher(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps({"version": 2, "fingerprints": [], "rules": [{"id": "SP101"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_baseline_fingerprints(path)
            path.write_text(
                json.dumps({"version": 2, "fingerprints": [], "rules": [{"reason": "no matcher"}]}),
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_baseline_fingerprints(path)

    def test_rule_globs_suppress_matching_findings(self):
        source = "result = " + "ev" + "al(value)\n"
        candidates = self.findings("tmp", source)
        baseline = SuppressionBaseline(
            fingerprints={},
            rules=(
                SuppressionRule(rule_id="SP101", reason="accepted dev tooling"),
                SuppressionRule(rule_id="SP102", path="tests/**", reason="test harness"),
                SuppressionRule(rule_id="SP1*", evidence="*value*", reason="reviewed"),
            ),
        )
        active, suppressed = deduplicate_and_suppress_findings(candidates, baseline)
        self.assertFalse(active)
        self.assertTrue(all(reason for _finding, reason in suppressed))

    def test_rule_for_other_path_does_not_suppress(self):
        source = "result = " + "ev" + "al(value)\n"
        candidates = self.findings("tmp", source)
        baseline = SuppressionBaseline(
            fingerprints={},
            rules=(SuppressionRule(rule_id="SP101", path="tests/**", reason="test harness"),),
        )
        active, suppressed = deduplicate_and_suppress_findings(candidates, baseline)
        self.assertTrue(active)
        self.assertFalse(suppressed)

    def test_malformed_baseline_is_invalid_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline_fingerprints(path)
            path.write_text(json.dumps({"fingerprints": "not-a-list"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_baseline_fingerprints(path)

    def test_main_cli_round_trip_with_show_suppressed(self):
        source = "result = " + "ev" + "al(value)\n"
        with make_repo({"app.py": source}) as tmp:
            baseline_path = Path(tmp) / "baseline.json"
            with contextlib.redirect_stdout(io.StringIO()):
                main(
                    [
                        tmp,
                        "--format",
                        "json",
                        "--fail-on",
                        "none",
                        "--baseline-out",
                        str(baseline_path),
                        "--baseline-reason",
                        "accepted dev loop",
                    ]
                )
                payload = json.loads(baseline_path.read_text(encoding="utf-8"))
                self.assertEqual(payload["version"], 2)
                self.assertTrue(payload["fingerprints"])
                self.assertTrue(
                    all(entry["reason"] == "accepted dev loop" for entry in payload["fingerprints"])
                )

                without_flag = json.loads(self.run_scan(tmp, baseline_path, show_suppressed=False))
                with_flag = json.loads(self.run_scan(tmp, baseline_path, show_suppressed=True))
            self.assertNotIn("suppressed_findings", without_flag)
            self.assertNotIn("SP101", [f["rule_id"] for f in without_flag["findings"]])
            self.assertIn("suppressed_findings", with_flag)
            self.assertTrue(
                all(
                    entry["suppression_reason"] == "accepted dev loop"
                    for entry in with_flag["suppressed_findings"]
                )
            )
            self.assertEqual(
                with_flag["summary"]["suppressed"], len(with_flag["suppressed_findings"])
            )

    def run_scan(self, tmp: str, baseline_path: Path, *, show_suppressed: bool) -> str:
        import subprocess

        arguments = [
            sys.executable,
            str(ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"),
            tmp,
            "--format",
            "json",
            "--fail-on",
            "none",
            "--baseline",
            str(baseline_path),
        ]
        if show_suppressed:
            arguments.append("--show-suppressed")
        result = subprocess.run(arguments, capture_output=True, text=True, shell=False)  # noqa: S603 - fixed argv in a test fixture
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_sarif_marks_suppressed_findings(self):
        source = "result = " + "ev" + "al(value)\n"
        candidates = self.findings("tmp", source)
        baseline = SuppressionBaseline(
            fingerprints={},
            rules=(SuppressionRule(rule_id="SP101", reason="accepted dev tooling"),),
        )
        active, suppressed = deduplicate_and_suppress_findings(candidates, baseline)
        sarif = build_sarif_report(active, suppressed=suppressed)
        marked = [result for result in sarif["runs"][0]["results"] if "suppressions" in result]
        self.assertEqual(len(marked), len(suppressed))
        self.assertEqual(marked[0]["suppressions"][0]["kind"], "external")
        self.assertEqual(marked[0]["suppressions"][0]["justification"], "accepted dev tooling")

    def test_baseline_file_inside_root_is_excluded_from_scan(self):
        source = "result = " + "ev" + "al(value)\n"
        with make_repo({"app.py": source}) as tmp:
            baseline_path = Path(tmp) / "baseline.json"
            with contextlib.redirect_stdout(io.StringIO()):
                main(
                    [
                        tmp,
                        "--format",
                        "json",
                        "--fail-on",
                        "none",
                        "--baseline-out",
                        str(baseline_path),
                    ]
                )
                _, stats = scan_repository(Path(tmp), excluded_paths=frozenset({"baseline.json"}))
            self.assertEqual(stats["completeness"]["baseline_excluded"], 1)

    def test_scanner_version_major_mismatch_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps({"version": 2, "scanner_version": "9.0.0", "fingerprints": []}),
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                baseline = load_baseline_fingerprints(path)
                from scan_repo import VERSION

                self.assertNotEqual(
                    baseline.scanner_version.split(".", 1)[0], VERSION.split(".", 1)[0]
                )
            # The warning itself is emitted by main(); loading stays silent.

    def test_rules_passthrough_into_baseline_out(self):
        source = "result = " + "ev" + "al(value)\n"
        with make_repo({"app.py": source}) as tmp:
            existing = Path(tmp) / "baseline.json"
            existing.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "scanner_version": scan_repo.VERSION,
                        "rules": [{"id": "SP102", "reason": "shell allowed in fixtures"}],
                        "fingerprints": [],
                    }
                ),
                encoding="utf-8",
            )
            regenerated = Path(tmp) / "baseline-out.json"
            with contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(
                    [
                        tmp,
                        "--format",
                        "json",
                        "--fail-on",
                        "none",
                        "--baseline",
                        str(existing),
                        "--baseline-out",
                        str(regenerated),
                    ]
                )
            self.assertEqual(exit_code, 0)
            payload = json.loads(regenerated.read_text(encoding="utf-8"))
            self.assertEqual(payload["rules"][0]["id"], "SP102")
            self.assertEqual(payload["rules"][0]["reason"], "shell allowed in fixtures")


class EvalDatasetScopeTests(unittest.TestCase):
    def test_eval_dataset_paths_are_test_scope(self):
        self.assertEqual(determine_scope("evals/evals.json"), "test")
        self.assertEqual(determine_scope("eval/dataset.jsonl"), "test")
        self.assertEqual(determine_scope("services/evals/dataset.json"), "test")
        self.assertEqual(determine_scope("src/evals.json"), "app")
        self.assertEqual(determine_scope("evals/other.json"), "app")

    def test_jsonl_files_are_scannable_text(self):
        self.assertTrue(scan_repo.is_text_file(Path("benchmarks/labels/clean-corpus.jsonl")))
        self.assertTrue(scan_repo.is_text_file(Path("eval/dataset.jsonl")))

    def test_findings_in_eval_datasets_do_not_block_the_gate(self):
        source = json.dumps({"api_key": "K7mQ2xR9" + "nP4wL8sT3vY1"})
        findings, _ = scan_repository_root(source)
        self.assertTrue(any(item.rule_id == "SP003" for item in findings), findings)
        self.assertTrue(all(item.scope == "test" for item in findings))
        self.assertFalse(
            scan_repo.gate_failed(findings, "high"),
            "eval-dataset findings must not block the default gate",
        )
        self.assertTrue(
            scan_repo.gate_failed(findings, "high", include_tests=True),
            "include-tests must still surface them",
        )

    def test_secrets_inside_eval_datasets_are_still_reported(self):
        key = "".join(("AKIA", "B2C3D4E5F6G7H8I9"))
        findings, _ = scan_repository_root(json.dumps({"ground_truth": key}))
        self.assertTrue(any(item.rule_id == "SP002" for item in findings))


def scan_repository_root(source: str, name: str = "evals/evals.json"):
    with make_repo({name: source}) as tmp:
        findings, _stats = scan_repository(Path(tmp))
        return findings, tmp


if __name__ == "__main__":
    unittest.main()
