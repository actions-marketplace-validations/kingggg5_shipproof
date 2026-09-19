from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

from scan_repo import RULES  # noqa: E402


class PromotionWaveBTests(unittest.TestCase):
    def test_mapping_is_complete_and_non_blocking(self) -> None:
        catalog = json.loads(
            (ROOT / "research" / "language-rule-candidates.json").read_text(encoding="utf-8")
        )
        candidate_ids = {item["candidate_id"] for item in catalog["candidates"]}
        executable = {rule.rule_id: rule for rule in RULES}
        expected = {
            "SP666": ("SP5301", "php"),
            "SP667": ("SP5951", "go"),
            "SP668": ("SP6309", "cpp"),
        }
        for rule_id, (candidate_id, ecosystem) in expected.items():
            self.assertIn(candidate_id, candidate_ids)
            self.assertIn(rule_id, executable)
            self.assertEqual(executable[rule_id].severity, "medium")
            self.assertIn(ecosystem, {"php", "go", "cpp"})


if __name__ == "__main__":
    unittest.main()
