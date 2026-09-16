"""Q02 acceptance: external comment anchor validation."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import comment_anchors as anchors  # noqa: E402


def make_tree(files: dict[str, bytes | str]) -> tempfile.TemporaryDirectory:
    tmp = tempfile.TemporaryDirectory()
    root = Path(tmp.name)
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return tmp


def check(comments, **kwargs):
    kwargs.setdefault("revision", "rev-1")
    kwargs.setdefault("expect_revision", "rev-1")
    return anchors.validate_comments(comments, **kwargs)


class AnchorValidationTests(unittest.TestCase):
    def test_exact_claim_resolves(self):
        with make_tree({"app.py": "a = 1\nb = 2\nc = 3\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 2,
                        "end_line": 2,
                        "excerpt": "b = 2\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "resolved")
        self.assertTrue(result["inline_eligible"])
        self.assertTrue(result["claimed_range_valid"])
        self.assertFalse(result["relocated"])
        self.assertEqual(result["resolved_start_line"], 2)

    def test_repeated_code_in_one_file_is_unresolved(self):
        body = "value = compute(x)\nvalue = compute(x)\n"
        with make_tree({"app.py": "head\n" + body + "tail\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 2,
                        "end_line": 2,
                        "excerpt": "value = compute(x)\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        # Even a matching claimed line cannot establish a unique anchor.
        self.assertEqual(result["anchor_status"], "unresolved")
        with make_tree({"app.py": "head\n" + body + "tail\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 9,
                        "end_line": 9,
                        "excerpt": "value = compute(x)\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "unresolved")
        self.assertFalse(result["inline_eligible"])
        self.assertIn("ambiguous", " ".join(result["reasons"]))

    def test_repeated_code_across_files_is_unresolved(self):
        with make_tree({"a.py": "token = 1\n", "b.py": "token = 1\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "a.py",
                        "side": "new",
                        "start_line": 5,
                        "end_line": 5,
                        "excerpt": "token = 1\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "unresolved")
        self.assertFalse(result["inline_eligible"])

    def test_unicode_path_and_content_resolve(self):
        with make_tree({" fé.py": "café = 1\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": " fé.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "café = 1\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "resolved")
        self.assertTrue(result["inline_eligible"])

    def test_crlf_file_matches_lf_excerpt(self):
        with make_tree({"app.py": b"a = 1\r\nb = 2\r\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 2,
                        "end_line": 2,
                        "excerpt": "b = 2\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "resolved")

    def test_old_side_deletion_resolves_against_old_tree(self):
        old_files = {"app.py": "keep = 1\nremove = 2\n"}
        new_files = {"app.py": "keep = 1\n"}
        with make_tree(old_files) as old, make_tree(new_files) as new:
            report = check(
                [
                    {
                        "id": "C-old",
                        "path": "app.py",
                        "side": "old",
                        "start_line": 2,
                        "end_line": 2,
                        "excerpt": "remove = 2\n",
                    },
                    {
                        "id": "C-new",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 2,
                        "end_line": 2,
                        "excerpt": "remove = 2\n",
                    },
                ],
                new_root=Path(new),
                old_root=Path(old),
            )
        by_id = {item["id"]: item for item in report["results"]}
        self.assertEqual(by_id["C-old"]["anchor_status"], "resolved")
        self.assertEqual(by_id["C-old"]["resolved_side"], "old")
        self.assertTrue(by_id["C-old"]["inline_eligible"])
        self.assertEqual(by_id["C-new"]["anchor_status"], "unresolved")
        self.assertFalse(by_id["C-new"]["inline_eligible"])

    def test_renamed_path_relocates_with_record(self):
        with (
            make_tree({"old_name.py": "unique_body = 1\n"}) as old,
            make_tree({"new_name.py": "unique_body = 1\n"}) as new,
        ):
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "old_name.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "unique_body = 1\n",
                    }
                ],
                new_root=Path(new),
                old_root=Path(old),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "resolved")
        self.assertTrue(result["relocated"])
        self.assertEqual(result["resolved_path"], "new_name.py")
        self.assertFalse(result["claimed_range_valid"])
        self.assertTrue(result["inline_eligible"])

    def test_rename_out_of_scope_is_unresolved(self):
        with make_tree({"moved.py": "unique_body = 1\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "old.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "unique_body = 1\n",
                    }
                ],
                new_root=Path(tmp),
                new_selected=["other.py"],
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "unresolved")
        self.assertFalse(result["inline_eligible"])

    def test_stale_revision_is_unresolved(self):
        with make_tree({"app.py": "a = 1\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "a = 1\n",
                    }
                ],
                new_root=Path(tmp),
                revision="rev-1",
                expect_revision="rev-2",
            )
        self.assertFalse(report["revision_matches"])
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "unresolved")
        self.assertFalse(result["inline_eligible"])
        self.assertIn("stale", " ".join(result["reasons"]))

    def test_fabricated_range_is_unresolved(self):
        with make_tree({"app.py": "a = 1\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 50,
                        "end_line": 50,
                        "excerpt": "invented = true\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "unresolved")
        self.assertFalse(result["inline_eligible"])

    def test_claimed_numbers_are_revalidated(self):
        # Right excerpt, wrong line numbers: must not blindly trust the claim.
        with make_tree({"app.py": "one\ntwo\nthree\n"}) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "three\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "resolved")
        self.assertEqual(result["resolved_start_line"], 3)
        self.assertFalse(result["claimed_range_valid"])
        self.assertTrue(result["relocated"])

    def test_malformed_anchors_raise(self):
        with make_tree({"app.py": "a = 1\n"}) as tmp:
            bad = [
                {
                    "id": "C1",
                    "path": "app.py",
                    "side": "sideways",
                    "start_line": 1,
                    "end_line": 1,
                    "excerpt": "a = 1\n",
                },
                {
                    "id": "C2",
                    "path": "app.py",
                    "side": "new",
                    "start_line": 2,
                    "end_line": 1,
                    "excerpt": "a = 1\n",
                },
                {
                    "id": "C3",
                    "path": "app.py",
                    "side": "new",
                    "start_line": 1,
                    "end_line": 2,
                    "excerpt": "a = 1\n",
                },
            ]
            for index, comment in enumerate(bad):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    check([comment], new_root=Path(tmp))

    def test_unresolved_never_inline_eligible(self):
        with make_tree({"a.py": "same = 1\n", "b.py": "same = 1\n"}) as tmp:
            report = check(
                [
                    {
                        "id": f"C{i}",
                        "path": "missing.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "same = 1\n",
                    }
                    for i in range(3)
                ],
                new_root=Path(tmp),
            )
        for result in report["results"]:
            self.assertEqual(result["anchor_status"], "unresolved")
            self.assertFalse(result["inline_eligible"])
            self.assertIsNone(result["resolved_path"])

    def test_vcs_internals_are_not_search_scope(self):
        with make_tree(
            {
                "app.py": "unique_anchor_body = 1\n",
                ".git/objects/pack": "unique_anchor_body = 1\n",
            }
        ) as tmp:
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "app.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "unique_anchor_body = 1\n",
                    }
                ],
                new_root=Path(tmp),
            )
        (result,) = report["results"]
        self.assertEqual(result["anchor_status"], "resolved")
        self.assertTrue(report["scope_complete"])

    def test_capped_scope_cannot_claim_uniqueness(self):
        with (
            make_tree({"app.py": "cap_anchor = 1\n"}) as tmp,
            mock.patch.object(anchors, "MAX_SCOPE_FILES", 0),
        ):
            report = check(
                [
                    {
                        "id": "C1",
                        "path": "elsewhere.py",
                        "side": "new",
                        "start_line": 1,
                        "end_line": 1,
                        "excerpt": "cap_anchor = 1\n",
                    }
                ],
                new_root=Path(tmp),
                new_selected=["app.py"],
            )
        (result,) = report["results"]
        # The excerpt exists but the capped scope cannot prove uniqueness.
        self.assertFalse(report["scope_complete"])
        self.assertEqual(result["anchor_status"], "unresolved")
        self.assertFalse(result["inline_eligible"])


if __name__ == "__main__":
    unittest.main()
