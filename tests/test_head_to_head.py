from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "benchmarks" / "head_to_head.py"
SPEC = importlib.util.spec_from_file_location("head_to_head", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load head-to-head harness")
head_to_head = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = head_to_head
SPEC.loader.exec_module(head_to_head)


class FileMetricsTests(unittest.TestCase):
    def test_perfect_detection(self):
        metrics = head_to_head.compute_file_metrics(["app.js"], ["app.js"], 3)
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["file_precision"], 1.0)
        self.assertEqual(metrics["file_recall"], 1.0)
        self.assertEqual(metrics["file_f1"], 1.0)
        self.assertEqual(metrics["true_negatives"], 2)

    def test_partial_and_clean_corpus_scoring(self):
        metrics = head_to_head.compute_file_metrics(["app.js", "util.js"], ["app.py", "util.js"], 4)
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["false_positives"], 1)
        self.assertEqual(metrics["false_negatives"], 1)
        self.assertEqual(metrics["file_precision"], 0.5)
        self.assertEqual(metrics["file_recall"], 0.5)
        self.assertEqual(metrics["true_negatives"], 1)

    def test_clean_corpus_needs_no_labels(self):
        metrics = head_to_head.compute_file_metrics([], [], 5)
        self.assertIsNone(metrics["file_precision"])
        self.assertIsNone(metrics["file_recall"])
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["true_negatives"], 5)


class LabelLoadingTests(unittest.TestCase):
    def test_missing_label_file_fails_closed(self):
        with self.assertRaises(FileNotFoundError):
            head_to_head.load_labels(ROOT / "does-not-exist.json", [ROOT / "fixtures"])

    def test_default_labels_cover_the_fixture_corpora(self):
        labels = head_to_head.load_labels(
            head_to_head.DEFAULT_LABELS,
            [
                ROOT / "fixtures" / "vulnerable-node-api",
                ROOT / "fixtures" / "vulnerable-python-api",
                ROOT / "fixtures" / "secure-node-api",
            ],
        )
        self.assertEqual(labels["vulnerable-node-api"]["positive_files"], ["app.js"])
        self.assertEqual(labels["vulnerable-python-api"]["positive_files"], ["app.py"])
        self.assertEqual(labels["secure-node-api"]["positive_files"], [])
        self.assertEqual(
            labels["vulnerable-node-api"]["positive_lines"],
            [
                {"path": "app.js", "line": 3, "rule_id": "SP103"},
                {"path": "app.js", "line": 6, "rule_id": "SP104"},
            ],
        )

    def test_schema_2_labels_cannot_include_positive_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / "demo"
            corpus.mkdir()
            (corpus / "app.js").write_text("const value = 1;\n", encoding="utf-8")
            labels_path = Path(directory) / "labels.json"
            labels_path.write_text(
                json.dumps(
                    {
                        "schema_version": 2,
                        "corpora": {
                            "demo": {
                                "positive_files": ["app.js"],
                                "context_only_files": [],
                                "positive_lines": [{"path": "app.js", "line": 1}],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "schema_version 2"):
                head_to_head.load_labels(labels_path, [corpus])

    def test_line_metrics_score_path_and_line_without_rule_ids(self):
        metrics = head_to_head.compute_line_metrics(
            [{"path": "sink.js", "line": 4, "rule_id": "other.rule"}],
            [{"path": "sink.js", "line": 4, "rule_id": "SP103"}],
        )
        self.assertEqual(metrics["true_positives"], 1)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)
        self.assertEqual(metrics["line_precision"], 1.0)
        self.assertEqual(metrics["line_recall"], 1.0)

    def test_wrong_line_is_a_line_false_positive_and_false_negative(self):
        metrics = head_to_head.compute_line_metrics(
            [{"path": "sink.js", "line": 9}],
            [{"path": "sink.js", "line": 4}],
        )
        self.assertEqual(metrics["true_positives"], 0)
        self.assertEqual(metrics["false_positives"], 1)
        self.assertEqual(metrics["false_negatives"], 1)
        self.assertEqual(metrics["line_precision"], 0.0)
        self.assertEqual(metrics["line_recall"], 0.0)

    def test_shipproof_leg_hits_labeled_crossfile_sink_lines(self):
        corpus = ROOT / "fixtures" / "node-taint-crossfile"
        result = head_to_head.run_shipproof(corpus, repeat=1)
        labels = head_to_head.load_labels(head_to_head.DEFAULT_LABELS, [corpus])
        metrics = head_to_head.compute_line_metrics(
            result["line_hits"],
            labels["node-taint-crossfile"]["positive_lines"],
            labels["node-taint-crossfile"]["context_only_files"],
        )
        self.assertEqual(metrics["line_precision"], 1.0)
        self.assertEqual(metrics["line_recall"], 1.0)
        self.assertGreaterEqual(metrics["true_positives"], 4)

    def test_context_only_files_do_not_reduce_sink_location_recall(self):
        metrics = head_to_head.compute_file_metrics(["sink.js"], ["sink.js"], 3, ["source.js"])
        self.assertEqual(metrics["file_recall"], 1.0)
        self.assertEqual(metrics["true_negatives"], 1)
        self.assertEqual(metrics["context_only_files"], 1)


class ShipProofLegTests(unittest.TestCase):
    def test_shipproof_leg_flags_the_labeled_file(self):
        corpus = ROOT / "fixtures" / "vulnerable-python-api"
        result = head_to_head.run_shipproof(corpus, repeat=1)
        self.assertEqual(result["tool"], "shipproof")
        self.assertEqual(result["files_flagged"], ["app.py"])
        self.assertGreater(result["findings"], 0)
        self.assertGreater(result["median_seconds"], 0)
        self.assertEqual(len(result["samples_seconds"]), 1)
        self.assertGreater(result["files_scanned"], 0)


class SemgrepLegTests(unittest.TestCase):
    def test_command_uses_one_corpus_argument_and_absolute_configs(self):
        corpus = ROOT / "fixtures" / "secure-node-api"
        config = ROOT / "benchmarks" / "semgrep-comparison" / "rules.yml"
        command = head_to_head.build_semgrep_command(corpus, [str(config)])
        self.assertEqual(command[-1], corpus.name)
        self.assertEqual(command.count(corpus.name), 1)
        self.assertEqual(command[-3:-1], ["--config", str(config.resolve())])


class RenderingTests(unittest.TestCase):
    def test_markdown_render_includes_every_row(self):
        markdown = head_to_head.render_markdown(
            [
                {
                    "tool": "shipproof",
                    "corpus": "demo",
                    "result": {"median_seconds": 1.5, "findings": 3, "files_flagged": ["a.py"]},
                    "metrics": head_to_head.compute_file_metrics(["a.py"], ["a.py"], 2),
                }
            ]
        )
        self.assertIn("| Tool | Corpus | Median seconds |", markdown)
        self.assertIn("| shipproof | demo | 1.5 | 3 | 1 | 0 | 0 | 1 |", markdown)

    def test_tree_digest_is_stable_for_the_same_corpus(self):
        corpus = ROOT / "fixtures" / "secure-node-api"
        self.assertEqual(head_to_head.sha256_tree(corpus), head_to_head.sha256_tree(corpus))


class MainTests(unittest.TestCase):
    def test_main_runs_shipproof_only_and_exits_zero(self):
        corpus = ROOT / "fixtures" / "secure-node-api"
        self.assertEqual(head_to_head.main([str(corpus), "--repeat", "1", "--format", "json"]), 0)

    def test_main_rejects_missing_corpus(self):
        self.assertEqual(head_to_head.main([str(ROOT / "missing-corpus")]), 2)


if __name__ == "__main__":
    unittest.main()
