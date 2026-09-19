from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "eval-shadow-prototypes.py"
SPEC = importlib.util.spec_from_file_location("eval_shadow_prototypes", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load shadow prototype harness")
shadow = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = shadow
SPEC.loader.exec_module(shadow)


class ShadowPrototypeTests(unittest.TestCase):
    def test_fixture_ready_prototypes_stay_advisory(self):
        payload = shadow.evaluate()
        ids = [item["candidate_id"] for item in payload["candidates"]]
        self.assertEqual(ids, ["SP5301", "SP5951", "SP6309"])
        self.assertEqual(payload["promoted_ids"], [])
        for item in payload["candidates"]:
            self.assertEqual(item["status"], "advisory_only")
            self.assertFalse(item["promoted"])
            self.assertEqual(item["polarity_mismatches"], [])
            self.assertGreaterEqual(item["polarity"]["true_positive"], 2)
            self.assertGreaterEqual(item["polarity"]["true_negative"], 4)

    def test_synthetic_fixtures_are_scored_without_promotion(self):
        payload = shadow.evaluate()
        by_id = {item["candidate_id"]: item for item in payload["candidates"]}
        self.assertGreaterEqual(len(by_id["SP5301"]["synthetic_fixtures"]["hits"]), 1)
        self.assertGreaterEqual(len(by_id["SP5951"]["synthetic_fixtures"]["hits"]), 1)
        self.assertGreaterEqual(len(by_id["SP6309"]["synthetic_fixtures"]["hits"]), 1)
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "shadow.json"
            previous = sys.argv
            old_stdout = sys.stdout
            try:
                sys.argv = [
                    "eval-shadow-prototypes.py",
                    "--json",
                    "--write-report",
                    str(report),
                ]
                sys.stdout = io.StringIO()
                self.assertEqual(shadow.main(), 0)
            finally:
                sys.stdout = old_stdout
                sys.argv = previous
            saved = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(saved["verdict"], "PASS_WITH_EVIDENCE")
            self.assertEqual(saved["promoted_ids"], [])


if __name__ == "__main__":
    unittest.main()
