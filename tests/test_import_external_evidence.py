from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "import_external_evidence.py"
SPEC = importlib.util.spec_from_file_location("import_external_evidence", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load external evidence importer")
importer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = importer
SPEC.loader.exec_module(importer)


class ExternalEvidenceImportTests(unittest.TestCase):
    def test_valid_envelope_keeps_original_rule_ids(self):
        report = importer.load_envelope(
            ROOT / "fixtures" / "external-evidence" / "valid-envelope.json"
        )
        self.assertEqual(report["imported_tool"]["name"], "example-linter")
        self.assertEqual(report["findings"][0]["original_rule_id"], "EX-001")
        self.assertTrue(report["findings"][0]["imported"])
        self.assertEqual(report["findings"][0]["proof_level"], "external")
        self.assertIn("[REDACTED]", report["findings"][0]["message"])
        self.assertNotEqual(report["tool"]["name"], "example-linter")

    def test_shipproof_identity_and_missing_digest_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "tool": {"name": "ShipProof", "version": "1.2.3", "command": "lint"},
                        "verdict": "PASS",
                        "limitations": ["no"],
                        "target_digest": "aa" * 32,
                        "config_digest": "bb" * 32,
                        "captured_at": "2026-09-15T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ShipProof tool identity"):
                importer.load_envelope(path)
            path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "tool": {"name": "other", "version": "1.2.3", "command": "lint"},
                        "verdict": "PASS",
                        "limitations": ["no"],
                        "target_digest": "not-a-digest",
                        "config_digest": "bb" * 32,
                        "captured_at": "2026-09-15T00:00:00Z",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "target_digest"):
                importer.load_envelope(path)


if __name__ == "__main__":
    unittest.main()
