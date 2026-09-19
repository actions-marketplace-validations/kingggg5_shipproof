from __future__ import annotations

import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import archive_inspect  # noqa: E402
import scan_repo  # noqa: E402
from scan_repo import scan_repository  # noqa: E402


class ArchiveInspectTests(unittest.TestCase):
    def test_default_scan_still_omits_zip_containers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "payload.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("inner.py", "value = 1\n")
            _, stats = scan_repository(root)
            completeness = stats["completeness"]
            self.assertFalse(completeness["is_complete"])
            self.assertEqual(completeness["reasons"], ["containers"])
            self.assertEqual(completeness["containers"], 1)

    def test_inspect_archives_scans_text_members_and_can_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "payload.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("inner.py", "value = 1\n")
            findings, stats = scan_repository(root, inspect_archives=True)
            completeness = stats["completeness"]
            self.assertTrue(completeness["is_complete"], completeness)
            self.assertEqual(completeness["containers"], 0)
            self.assertGreaterEqual(stats["files_scanned"], 1)
            self.assertEqual(findings, [])

    def test_inspect_archives_reports_findings_on_virtual_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "payload.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr(
                    "inner.py",
                    "try:\n    value = 1\nexcept Exception:\n    pass\n",
                )
            findings, stats = scan_repository(root, inspect_archives=True)
            self.assertTrue(
                any(item.path == "payload.zip!/inner.py" for item in findings), findings
            )
            self.assertEqual(stats["completeness"]["containers"], 0)

    def test_compression_bomb_is_rejected(self):
        payload = b"a" * (20 * 1024)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as handle:
            handle.writestr("bomb.txt", payload)
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bomb.zip"
            archive.write_bytes(buffer.getvalue())
            with zipfile.ZipFile(archive) as handle:
                info = handle.getinfo("bomb.txt")
                self.assertGreater(
                    info.file_size, info.compress_size * archive_inspect.MAX_COMPRESSION_RATIO
                )
            inspection = archive_inspect.inspect_zip_archive(
                archive, "bomb.zip", text_suffixes=scan_repo.TEXT_SUFFIXES
            )
            self.assertFalse(inspection.complete)
            self.assertEqual(inspection.reason, "bomb")
            self.assertEqual(inspection.members, ())

    def test_zip_slip_and_nested_zip_stay_incomplete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "payload.zip"
            with zipfile.ZipFile(archive, "w") as handle:
                handle.writestr("../escape.py", "value = 1\n")
                handle.writestr("nested.zip", b"PK\x03\x04")
            inspection = archive_inspect.inspect_zip_archive(
                archive, "payload.zip", text_suffixes=scan_repo.TEXT_SUFFIXES
            )
            self.assertFalse(inspection.complete)
            self.assertEqual(inspection.members, ())


if __name__ == "__main__":
    unittest.main()
