"""Q03 paired regression: fixture strings vs code scanned by the real walker.

For each cohort rule, the exact curated sources from
``scripts/build_legacy_pattern_contracts.py`` are written to disk and scanned
through ``scan_repository`` (the production walker). The vulnerable source
must raise its rule; the realistic safe counterpart must stay silent for it.
"""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT / "scripts"))

import scan_repo  # noqa: E402

BUILDER_SPEC = importlib.util.spec_from_file_location(
    "build_legacy_pattern_contracts",
    ROOT / "scripts" / "build_legacy_pattern_contracts.py",
)
if BUILDER_SPEC is None or BUILDER_SPEC.loader is None:
    raise RuntimeError("could not load legacy pattern contract builder")
builder = importlib.util.module_from_spec(BUILDER_SPEC)
sys.modules[BUILDER_SPEC.name] = builder
BUILDER_SPEC.loader.exec_module(builder)

COHORT_1 = ("SP101", "SP103", "SP138", "SP151", "SP163")
COHORT_2 = ("SP104", "SP201", "SP105", "SP144", "SP164")
COHORT_3 = ("SP122", "SP165", "SP110", "SP124", "SP175")
COHORT_4 = ("SP141", "SP142", "SP143", "SP123", "SP190")
COHORT_5 = ("SP158",)
COHORT = COHORT_1 + COHORT_2 + COHORT_3 + COHORT_4 + COHORT_5
# The production walker routes rules by file suffix; pair files must use an
# extension each rule actually scans. SP190 ships JS-shaped fixtures, which
# also keeps the Python parser ledger out of the picture.
COHORT_SUFFIX = {"SP124": ".js", "SP190": ".js"}


class WalkerPairTests(unittest.TestCase):
    def test_curated_sources_behave_through_the_walker(self):
        for rule_id in COHORT:
            with self.subTest(rule_id=rule_id):
                negatives = builder.CURATED_NEGATIVES[rule_id]
                positives = builder.CURATED_POSITIVES[rule_id]
                self.assertTrue(negatives)
                self.assertTrue(positives)
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    suffix = COHORT_SUFFIX.get(rule_id, ".py")
                    (root / f"safe{suffix}").write_text(negatives[0], encoding="utf-8")
                    (root / f"vuln{suffix}").write_text(positives[0], encoding="utf-8")
                    findings, stats = scan_repo.scan_repository(root)
                self.assertTrue(stats["completeness"]["is_complete"])
                by_path: dict[str, list] = {}
                for finding in findings:
                    if finding.rule_id == rule_id:
                        by_path.setdefault(finding.path, []).append(finding)
                self.assertEqual(
                    sorted(by_path),
                    [f"vuln{COHORT_SUFFIX.get(rule_id, '.py')}"],
                    f"{rule_id} must fire on vuln and stay silent on safe",
                )

    def test_safe_counterparts_raise_no_blocking_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for rule_id in COHORT:
                suffix = COHORT_SUFFIX.get(rule_id, ".py")
                (root / f"safe_{rule_id.lower()}{suffix}").write_text(
                    builder.CURATED_NEGATIVES[rule_id][0], encoding="utf-8"
                )
            findings, stats = scan_repo.scan_repository(root)
        self.assertTrue(stats["completeness"]["is_complete"])
        blocking = [finding for finding in findings if finding.severity in {"critical", "high"}]
        self.assertEqual(blocking, [])


if __name__ == "__main__":
    unittest.main()
