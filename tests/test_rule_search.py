"""Q07 acceptance: exact lookup, kind separation, limits, determinism."""

from __future__ import annotations

import sys
import unittest

ROOT = __import__("pathlib").Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import rule_search  # noqa: E402
from scan_repo import RULES  # noqa: E402


def executable_index():
    return rule_search.build_executable_index(
        list(RULES), lambda rule_id: next(r.remediation for r in RULES if r.rule_id == rule_id)
    )


class SearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.index = executable_index()

    def test_exact_lookup_passes_every_published_id(self):
        for rule in RULES:
            with self.subTest(rule_id=rule.rule_id):
                answer = rule_search.search(self.index, rule.rule_id, top_k=5)
                self.assertTrue(answer["results"])
                self.assertEqual(answer["results"][0]["rule_id"], rule.rule_id)
                self.assertEqual(answer["results"][0]["kind"], "executable")

    def test_exact_lookup_is_case_insensitive(self):
        answer = rule_search.search(self.index, "sp101", top_k=5)
        self.assertEqual(answer["results"][0]["rule_id"], "SP101")

    def test_cwe_lookup_is_deterministic(self):
        first = rule_search.search(self.index, "CWE-89", top_k=5)
        second = rule_search.search(self.index, "CWE-89", top_k=5)
        self.assertEqual(first, second)
        self.assertTrue(first["results"])
        self.assertTrue(all("89" in result["cwe"] for result in first["results"]))

    def test_unknown_and_empty_queries_have_tested_behavior(self):
        answer = rule_search.search(self.index, "zzzzqqqqxxxx", top_k=5)
        self.assertEqual(answer["results"], [])
        answer = rule_search.search(self.index, "   ", top_k=5)
        self.assertEqual(answer["results"], [])
        self.assertIn("reason", answer)

    def test_limits_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "top_k"):
            rule_search.search(self.index, "sql", top_k=500)
        with self.assertRaisesRegex(ValueError, "bytes"):
            rule_search.search(self.index, "x" * 3000, top_k=5)
        with self.assertRaisesRegex(ValueError, "string"):
            rule_search.search(self.index, None, top_k=5)  # type: ignore[arg-type]

    def test_ranking_is_deterministic(self):
        first = rule_search.search(self.index, "insecure randomness token", top_k=5)
        second = rule_search.search(self.index, "insecure randomness token", top_k=5)
        self.assertEqual(first, second)

    def test_results_carry_version_and_provenance(self):
        answer = rule_search.search(self.index, "sql injection", top_k=3)
        self.assertTrue(answer["results"])
        for result in answer["results"]:
            self.assertEqual(result["search_version"], rule_search.SEARCH_VERSION)
            self.assertTrue(result["provenance"])
            self.assertIn("score", result)

    def test_thai_query_finds_its_rule(self):
        answer = rule_search.search(self.index, "ตรวจ SQL ที่ต่อสตริงจากตัวแปร", top_k=5)
        self.assertIn("SP103", [result["rule_id"] for result in answer["results"]])

    def test_research_kind_never_presents_shipped_rules(self):
        candidates = [
            {
                "candidate_id": "SP4451",
                "ecosystem": "csharp",
                "source_id": "CWE-434",
                "batch_status": "rejected",
                "decision": "needs dataflow analysis, not a regex",
            }
        ]
        index = rule_search.build_research_index(candidates)
        answer = rule_search.search(index, "SP4451", top_k=5)
        self.assertEqual(answer["results"][0]["kind"], "research")
        self.assertEqual(answer["results"][0]["status"], "rejected")
        self.assertIn("warning", answer["results"][0])
        self.assertNotIn("rule_id", answer["results"][0])

    def test_example_kind_carries_reviewed_provenance(self):
        index = rule_search.build_example_index(
            [{"rule_id": "SP101", "polarity": "negative", "source": "ast.literal_eval"}]
        )
        answer = rule_search.search(index, "SP101", top_k=5)
        self.assertEqual(answer["results"][0]["kind"], "examples")
        self.assertIn("q03", answer["results"][0]["provenance"])


if __name__ == "__main__":
    unittest.main()
