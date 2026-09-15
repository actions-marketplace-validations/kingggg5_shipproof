"""Bounded ZIP/Office inspection. Never extracts to disk or executes members."""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from pathlib import Path

ZIP_INSPECTABLE_SUFFIXES = frozenset(
    {
        ".zip",
        ".docx",
        ".xlsx",
        ".pptx",
        ".jar",
        ".war",
        ".apk",
        ".ipa",
        ".aab",
        ".whl",
        ".egg",
    }
)
MAX_ARCHIVE_MEMBERS = 32
MAX_MEMBER_BYTES = 256 * 1024
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_MEMBER_NAME = 512
MIN_BOMB_UNCOMPRESSED = 10 * 1024


@dataclass(frozen=True)
class ArchiveMember:
    virtual_path: str
    source_text: str


@dataclass(frozen=True)
class ArchiveInspection:
    members: tuple[ArchiveMember, ...]
    complete: bool
    reason: str | None = None


def virtual_member_path(archive_relative: str, inner_name: str) -> str:
    return f"{archive_relative}!/{inner_name}"


def _posix_member_name(raw: str) -> str | None:
    if not isinstance(raw, str) or not raw or len(raw) > MAX_MEMBER_NAME:
        return None
    normalized = raw.replace("\\", "/")
    if normalized.startswith(("/", "\\")) or ":" in normalized:
        return None
    parts = [part for part in normalized.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def inspect_zip_archive(
    path: Path,
    archive_relative: str,
    *,
    text_suffixes: frozenset[str],
) -> ArchiveInspection:
    """Read scannable text members from a ZIP-based container in memory."""
    try:
        archive = zipfile.ZipFile(path, "r")
    except (OSError, zipfile.BadZipFile):
        return ArchiveInspection((), False, "invalid")
    with archive:
        return _inspect_open_zip(archive, archive_relative, text_suffixes=text_suffixes)


def _inspect_open_zip(
    archive: zipfile.ZipFile,
    archive_relative: str,
    *,
    text_suffixes: frozenset[str],
) -> ArchiveInspection:
    members: list[ArchiveMember] = []
    total_uncompressed = 0
    scanned = 0
    omitted = False
    try:
        infos = list(archive.infolist())
    except (OSError, zipfile.BadZipFile):
        return ArchiveInspection((), False, "invalid")
    for info in infos:
        name = _posix_member_name(info.filename)
        if name is None:
            omitted = True
            continue
        if info.is_dir() or name.endswith("/"):
            continue
        if info.flag_bits & 0x1:
            return ArchiveInspection((), False, "encrypted")
        uncompressed = int(info.file_size)
        compressed = int(info.compress_size)
        if uncompressed < 0 or compressed < 0:
            return ArchiveInspection((), False, "invalid")
        if uncompressed > MAX_MEMBER_BYTES:
            omitted = True
            continue
        if uncompressed >= MIN_BOMB_UNCOMPRESSED and (
            compressed == 0 or uncompressed > compressed * MAX_COMPRESSION_RATIO
        ):
            return ArchiveInspection((), False, "bomb")
        suffix = Path(name).suffix.lower()
        if suffix in ZIP_INSPECTABLE_SUFFIXES:
            omitted = True
            continue
        if suffix not in text_suffixes:
            continue
        if scanned >= MAX_ARCHIVE_MEMBERS:
            omitted = True
            continue
        if total_uncompressed + uncompressed > MAX_TOTAL_UNCOMPRESSED:
            omitted = True
            continue
        try:
            payload = archive.read(info)
        except (OSError, RuntimeError, zipfile.BadZipFile):
            omitted = True
            continue
        if len(payload) > MAX_MEMBER_BYTES:
            omitted = True
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            omitted = True
            continue
        members.append(
            ArchiveMember(virtual_member_path(archive_relative, name), text.replace("\r\n", "\n"))
        )
        scanned += 1
        total_uncompressed += len(payload)
    return ArchiveInspection(tuple(members), not omitted)
