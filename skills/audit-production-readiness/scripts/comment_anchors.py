#!/usr/bin/env python3
"""Validate external review comment anchors against the reviewed bytes (Q02).

Offline, read-only, dependency-free. Anchors carry a claimed revision, path,
side (old/new), line range, and bounded excerpt. Validation re-checks the
claimed line numbers against file content instead of trusting them: an anchor
resolves only when the excerpt matches exactly (after CRLF/LF normalization)
at one single location inside the allowed scope.

Rules:
  resolved   - excerpt matches at the claimed location, or matches at exactly
               one in-scope location (relocation is recorded, never silent).
  unresolved - zero matches (kept as a review question, never auto-published
               as an inline finding), multiple matches (ambiguous, including
               repeats inside one file), out-of-scope matches, stale revision,
               or incomplete search scope.
  Position-correct and allegation-correct stay separate: this module reports
  ``anchor_status`` only. Only ``resolved`` anchors are ``inline_eligible``.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import snapshot_identity as identity

ANCHOR_VERSION = "comment-anchor/1.0"
MAX_EXCERPT_BYTES = 4096
MAX_EXCERPT_LINES = 100
MAX_LINE = 10_000_000
MAX_SCOPE_FILES = 5000
MAX_SCOPE_BYTES = 1_000_000
# Version-control internals are never review scope; the scanner prunes them too.
PRUNE_DIRS = frozenset({".git", ".hg", ".svn"})
SIDES = frozenset({"old", "new"})


def normalize_lines(text: str) -> list[str]:
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def canonical_excerpt(excerpt: str) -> list[str]:
    lines = normalize_lines(excerpt)
    if lines and lines[-1] == "":
        lines = lines[:-1]
    return lines


def check_excerpt(excerpt: Any) -> list[str]:
    if not isinstance(excerpt, str) or not excerpt:
        raise ValueError("excerpt must be a non-empty string")
    if len(excerpt.encode("utf-8")) > MAX_EXCERPT_BYTES:
        raise ValueError(f"excerpt exceeds {MAX_EXCERPT_BYTES} bytes")
    lines = canonical_excerpt(excerpt)
    if not lines or len(lines) > MAX_EXCERPT_LINES:
        raise ValueError(f"excerpt must hold 1-{MAX_EXCERPT_LINES} lines")
    return lines


def check_range(start: Any, end: Any) -> tuple[int, int]:
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("start_line must be an integer")
    if isinstance(end, bool) or not isinstance(end, int):
        raise ValueError("end_line must be an integer")
    if not 1 <= start <= MAX_LINE or not 1 <= end <= MAX_LINE:
        raise ValueError("anchor range must hold positive line numbers")
    if start > end:
        raise ValueError("start_line must not exceed end_line")
    if end - start + 1 > MAX_EXCERPT_LINES:
        raise ValueError(f"anchor range exceeds {MAX_EXCERPT_LINES} lines")
    return start, end


def check_comment_shape(item: Any, index: int) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError(f"comments[{index}] must be an object")
    allowed = {"id", "path", "side", "start_line", "end_line", "excerpt"}
    unknown = set(item) - allowed
    if unknown:
        raise ValueError(f"comments[{index}] has unknown fields: {sorted(unknown)}")
    raw_path = item.get("path")
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError(f"comments[{index}].path must be a non-empty string")
    side = item.get("side")
    if side not in SIDES:
        raise ValueError(f"comments[{index}].side must be one of {sorted(SIDES)}")
    start, end = check_range(item.get("start_line"), item.get("end_line"))
    lines = check_excerpt(item.get("excerpt"))
    if len(lines) != end - start + 1:
        raise ValueError(
            f"comments[{index}] excerpt holds {len(lines)} lines but range covers {end - start + 1}"
        )
    comment_id = item.get("id", f"comment-{index}")
    if not isinstance(comment_id, str) or not comment_id:
        raise ValueError(f"comments[{index}].id must be a non-empty string")
    return {
        "id": comment_id,
        "path": unicodedata.normalize("NFC", raw_path),
        "side": side,
        "start_line": start,
        "end_line": end,
        "excerpt_lines": lines,
    }


@dataclass
class ScopeFile:
    relative: str
    lines: list[str] | None = None
    skipped: str | None = None


def collect_scope(tree: Path, selected: list[str] | None) -> tuple[list[ScopeFile], bool]:
    """List in-scope files. Returns (files, scope_complete).

    The file cap bounds work, not correctness: when the cap is hit the files
    collected so far are still returned (direct claimed-location matches stay
    verifiable) but the scope is incomplete, so uniqueness searches resolve to
    ``unresolved`` instead of claiming a single match.
    """
    if selected is not None:
        relatives = [unicodedata.normalize("NFC", entry) for entry in selected]
    else:
        relatives = []
        for path in tree.rglob("*"):
            if not path.is_file():
                continue
            try:
                relative = path.resolve().relative_to(tree).as_posix()
            except (OSError, ValueError):
                continue
            parts = relative.split("/")
            if any(part in PRUNE_DIRS for part in parts[:-1]):
                continue
            relatives.append(unicodedata.normalize("NFC", relative))
            if len(relatives) > MAX_SCOPE_FILES:
                break
        relatives.sort()
    complete = len(relatives) <= MAX_SCOPE_FILES
    files: list[ScopeFile] = []
    for relative in relatives[:MAX_SCOPE_FILES]:
        try:
            absolute = Path(relative)
            if absolute.is_absolute():
                files.append(ScopeFile(relative, skipped="absolute-path"))
                complete = False
                continue
            candidate = (tree / Path(*relative.split("/"))).resolve()
            if not identity.contains(tree, candidate):
                files.append(ScopeFile(relative, skipped="out-of-scope"))
                complete = False
                continue
            content = identity.read_bytes_guarded(candidate, MAX_SCOPE_BYTES)
        except (OSError, ValueError):
            files.append(ScopeFile(relative, skipped="unreadable"))
            complete = False
            continue
        # errors="replace" keeps ASCII excerpts searchable inside files with
        # undecodable bytes instead of discarding the whole file.
        files.append(
            ScopeFile(relative, normalize_lines(content.decode("utf-8", errors="replace")))
        )
    return files, complete


def find_block(lines: list[str], block: list[str]) -> list[int]:
    """Return 1-based start lines where block occurs contiguously."""
    width = len(block)
    if width == 0 or len(lines) < width:
        return []
    return [
        index + 1
        for index in range(len(lines) - width + 1)
        if lines[index : index + width] == block
    ]


@dataclass
class AnchorResult:
    comment_id: str
    anchor_status: str = "unresolved"
    reasons: list[str] = field(default_factory=list)
    resolved_path: str | None = None
    resolved_side: str | None = None
    resolved_start_line: int | None = None
    resolved_end_line: int | None = None
    claimed_range_valid: bool = False
    relocated: bool = False
    inline_eligible: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.comment_id,
            "anchor_status": self.anchor_status,
            "reasons": list(self.reasons),
            "resolved_path": self.resolved_path,
            "resolved_side": self.resolved_side,
            "resolved_start_line": self.resolved_start_line,
            "resolved_end_line": self.resolved_end_line,
            "claimed_range_valid": self.claimed_range_valid,
            "relocated": self.relocated,
            "inline_eligible": self.inline_eligible,
        }


def validate_anchor(
    comment: dict[str, Any],
    *,
    new_scope: list[ScopeFile],
    old_scope: list[ScopeFile],
    scope_complete: bool,
) -> AnchorResult:
    result = AnchorResult(comment_id=comment["id"])
    scope = new_scope if comment["side"] == "new" else old_scope
    by_path = {entry.relative: entry for entry in scope}
    claimed = by_path.get(comment["path"])
    block = comment["excerpt_lines"]
    width = len(block)

    def resolve(
        path: str,
        start: int,
        *,
        relocated: bool,
        claimed_valid: bool,
        note: str | None = None,
    ) -> AnchorResult:
        result.anchor_status = "resolved"
        result.resolved_path = path
        result.resolved_side = comment["side"]
        result.resolved_start_line = start
        result.resolved_end_line = start + width - 1
        result.claimed_range_valid = claimed_valid
        result.relocated = relocated
        result.inline_eligible = True
        if note:
            result.reasons.append(note)
        return result

    if claimed is not None and claimed.lines is not None:
        if comment["end_line"] <= len(claimed.lines):
            window = claimed.lines[comment["start_line"] - 1 : comment["end_line"]]
            if window == block:
                result.claimed_range_valid = True
        result.reasons.append(
            "excerpt does not match the claimed range; searching the allowed scope"
        )
    elif claimed is not None:
        result.reasons.append(f"claimed file is {claimed.skipped}; searching the allowed scope")
        if claimed.skipped == "out-of-scope":
            result.reasons.append("claimed path lies outside the allowed scope")
    else:
        result.reasons.append("claimed path is absent for this side; searching the allowed scope")

    if not scope_complete:
        result.reasons.append("search scope is incomplete; uniqueness cannot be proven")
        return result
    hits: list[tuple[str, int]] = []
    for entry in scope:
        if entry.lines is None:
            continue
        for start in find_block(entry.lines, block):
            hits.append((entry.relative, start))
    if len(hits) == 1:
        path, start = hits[0]
        same_spot = (
            claimed is not None and path == claimed.relative and start == comment["start_line"]
        )
        return resolve(
            path,
            start,
            relocated=not same_spot,
            claimed_valid=same_spot,
            note=None if same_spot else f"relocated from {comment['path']}:{comment['start_line']}",
        )
    if not hits:
        result.reasons.append(
            "no source match in scope; kept as a review question, not an inline finding"
        )
        return result
    locations = ", ".join(f"{path}:{start}" for path, start in hits[:5])
    if len(hits) > 5:
        locations += f" (+{len(hits) - 5} more)"
    result.reasons.append(f"ambiguous excerpt with {len(hits)} in-scope matches: {locations}")
    return result


def validate_comments(
    comments: list[Any],
    *,
    new_root: Path,
    old_root: Path | None = None,
    new_selected: list[str] | None = None,
    old_selected: list[str] | None = None,
    revision: str = "",
    expect_revision: str | None = None,
) -> dict[str, Any]:
    """Validate every comment anchor. Never raises for anchor mismatches."""
    if not isinstance(revision, str) or not revision or len(revision) > 128:
        raise ValueError("revision must be a non-empty string of at most 128 characters")
    new_tree = identity.resolve_root(new_root)
    old_tree = identity.resolve_root(old_root) if old_root is not None else new_tree
    if not isinstance(comments, list) or len(comments) > 500:
        raise ValueError("comments must be a list of at most 500 items")
    parsed = [check_comment_shape(item, index) for index, item in enumerate(comments)]
    revision_matches = expect_revision is not None and revision == expect_revision
    new_scope, new_complete = collect_scope(new_tree, new_selected)
    if old_tree == new_tree and old_selected == new_selected:
        old_scope, old_complete = new_scope, new_complete
    else:
        old_scope, old_complete = collect_scope(old_tree, old_selected)
    results: list[dict[str, Any]] = []
    for comment in parsed:
        complete = new_complete if comment["side"] == "new" else old_complete
        if comment["side"] == "old" and old_root is None:
            results.append(
                AnchorResult(
                    comment_id=comment["id"], reasons=["old-side source was not supplied"]
                ).as_dict()
            )
            continue
        if not revision_matches:
            results.append(
                AnchorResult(
                    comment_id=comment["id"],
                    reasons=["stale context: anchor revision does not match the reviewed revision"],
                ).as_dict()
            )
            continue
        results.append(
            validate_anchor(
                comment,
                new_scope=new_scope,
                old_scope=old_scope,
                scope_complete=complete,
            ).as_dict()
        )
    resolved = sum(1 for item in results if item["anchor_status"] == "resolved")
    return {
        "anchor_version": ANCHOR_VERSION,
        "revision": revision,
        "revision_matches": revision_matches,
        "scope_complete": new_complete and old_complete,
        "counts": {
            "total": len(results),
            "resolved": resolved,
            "unresolved": len(results) - resolved,
        },
        "results": results,
    }
