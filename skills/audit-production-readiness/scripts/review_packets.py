#!/usr/bin/env python3
"""Bounded review packets for the user's existing host agent (Q05).

Offline, read-only, dependency-free. A packet binds target/config identity
(Q01), selected findings with source anchors (Q02), deterministic related
files, source roles, redacted evidence, and open questions into a local
artifact the user's own agent workflow can consume. This module never sends
source anywhere; delivery is a local file the caller chose to write.

Bounds (prototype): at most 10 files and 128 KiB of source text per packet.
Anything dropped is recorded with reasons; a packet that dropped data never
claims to be complete. Token counts are labeled estimates.

Item lifecycle: selected -> scheduled -> completed/failed/deferred.
Cancellation, missing responses, and exhausted budgets never count as completed.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import snapshot_identity as identity

PACKET_VERSION = "review-packet/1.0"
MAX_FILES_PER_PACKET = 10
MAX_BYTES_PER_PACKET = 131072
MAX_PACKETS = 20
SECRET_VALUE_RE = re.compile(r"(?i)(?:sk-|ghp_|github_pat_|xox[baprs]-|Bearer\s+)[A-Za-z0-9._\-]+")

ITEM_STATUSES = frozenset({"selected", "scheduled", "completed", "failed", "deferred"})


def redact(text: str) -> str:
    return SECRET_VALUE_RE.sub("[REDACTED]", text)


def classify_role(relative: str) -> tuple[str, str]:
    """Source role is review context, never a gate permission."""
    normalized = unicodedata.normalize("NFC", relative.replace("\\", "/"))
    parts = normalized.split("/")
    name = parts[-1].lower()
    if parts[0] in {"tests"} or "test" in parts[1:-1]:
        return "test", "under a tests/ directory"
    if name.startswith(("test_", "test-")) or "_test." in name or "-test." in name:
        return "test", "test file naming"
    if parts[0] in {"examples"} or "/examples/" in f"/{normalized}/":
        return "example", "under an examples/ directory"
    if (
        "rule-contracts" in parts
        or "contract-fixtures" in parts
        or parts[0]
        in {
            "fixtures",
            "evals",
            "eval",
        }
    ):
        return "rule-data", "fixture or evaluation data path"
    if "generated" in name or name.endswith((".g.cs", ".generated.cs", ".pb.go")):
        return "generated", "generated-file naming"
    if parts[0] in {"docs", "website", "research", "benchmarks"}:
        return "example", "documentation or research path"
    if len(parts) == 1 or parts[0] not in {"skills", "scripts", "lib", "bin"}:
        return "app", "application source by default"
    return "app", "application source by default"


def _field(item: Any, name: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


@dataclass
class LedgerItem:
    fingerprint: str
    rule_id: str
    path: str
    line: int
    status: str = "selected"
    reasons: list[str] = field(default_factory=list)
    packet_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "path": self.path,
            "line": self.line,
            "status": self.status,
            "reasons": list(self.reasons),
            "packet_id": self.packet_id,
        }


def default_related(relative: str, tree: Path) -> list[str]:
    """Deterministic related files: same-directory siblings with code suffixes."""
    parent = Path(*relative.split("/")).parent if "/" in relative else Path(".")
    siblings: list[str] = []
    directory = tree / parent if str(parent) != "." else tree
    try:
        entries = sorted(directory.iterdir(), key=lambda p: p.name)
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file() or entry.name == Path(relative).name:
            continue
        if entry.suffix.lower() in {
            ".py",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".go",
            ".php",
            ".cs",
            ".java",
            ".rs",
            ".rb",
            ".sql",
        }:
            candidate = (f"{parent.as_posix()}/{entry.name}").removeprefix("./")
            siblings.append(unicodedata.normalize("NFC", candidate))
    return siblings[:4]


def _read_source(tree: Path, relative: str, limit: int) -> tuple[bytes | None, str | None]:
    try:
        candidate = (tree / Path(*relative.split("/"))).resolve()
    except (OSError, ValueError):
        return None, "unresolvable-path"
    if not identity.contains(tree, candidate):
        return None, "out-of-scope"
    try:
        return identity.read_bytes_guarded(candidate, limit), None
    except ValueError as exc:
        return None, str(exc)


def build_packets(
    root: Path,
    findings: Iterable[Any],
    *,
    policy: dict[str, Any] | None = None,
    scanner_version: str = "unknown",
    rules_identity: str = "unknown",
    anchors: dict[str, dict[str, Any]] | None = None,
    related_fn: Callable[[str, Path], list[str]] | None = None,
    max_files: int = MAX_FILES_PER_PACKET,
    max_bytes: int = MAX_BYTES_PER_PACKET,
    max_packets: int = MAX_PACKETS,
) -> dict[str, Any]:
    """Group findings into bounded packets with a full selection accounting."""
    tree = identity.resolve_root(root)
    for name, value, maximum in (
        ("max_files", max_files, MAX_FILES_PER_PACKET),
        ("max_bytes", max_bytes, MAX_BYTES_PER_PACKET),
        ("max_packets", max_packets, MAX_PACKETS),
    ):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer from 1 through {maximum}")
    related = related_fn or default_related
    ordered = sorted(
        findings,
        key=lambda item: (
            str(_field(item, "rule_id")),
            str(_field(item, "path")),
            int(_field(item, "line", 0) or 0),
            str(_field(item, "fingerprint")),
        ),
    )
    ledger = [
        LedgerItem(
            fingerprint=str(_field(item, "fingerprint")),
            rule_id=str(_field(item, "rule_id")),
            path=unicodedata.normalize("NFC", str(_field(item, "path")).replace("\\", "/")),
            line=int(_field(item, "line", 0) or 0),
        )
        for item in ordered
    ]
    by_directory: dict[str, list[LedgerItem]] = {}
    for entry in ledger:
        directory = entry.path.rpartition("/")[0] or "."
        by_directory.setdefault(directory, []).append(entry)
    packets: list[dict[str, Any]] = []
    packet_index = 0
    for directory in sorted(by_directory):
        if packet_index >= max_packets:
            break
        group = by_directory[directory]
        included: list[LedgerItem] = []
        files: dict[str, dict[str, Any]] = {}
        used_bytes = 0
        truncated = False
        reasons: list[str] = []
        wanted: list[str] = []
        for entry in group:
            wanted.append(entry.path)
            wanted.extend(related(entry.path, tree))
        seen: set[str] = set()
        queue = [path for path in wanted if not (path in seen or seen.add(path))]
        for relative in queue:
            if len(files) >= max_files:
                truncated = True
                reasons.append(f"file cap ({max_files}) reached; remaining files deferred")
                break
            content, error = _read_source(tree, relative, max_bytes)
            if content is None:
                truncated = True
                reasons.append(f"{relative}: source unavailable ({error})")
                continue
            if used_bytes + len(content) > max_bytes:
                truncated = True
                reasons.append(
                    f"byte cap ({max_bytes} bytes) reached at {relative}; remaining files deferred"
                )
                continue
            role, basis = classify_role(relative)
            files[relative] = {
                "path": relative,
                "role": role,
                "role_basis": basis,
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
                "text": redact(content.decode("utf-8", errors="replace")),
            }
            used_bytes += len(content)
        for entry in group:
            if entry.path in files:
                entry.status = "scheduled"
                entry.packet_id = f"packet-{packet_index + 1:03d}"
                included.append(entry)
            else:
                truncated = True
                entry.status = "deferred"
                entry.reasons.append("finding source not inside its packet bounds")
        if not included and truncated:
            for entry in group:
                if entry.status == "deferred":
                    entry.reasons.append("packet carried no scheduled items")
            continue
        if not included:
            continue
        packet_index += 1
        packet_id = f"packet-{packet_index:03d}"
        digest_inputs = sorted(files)
        packet_digest = hashlib.sha256(
            "\x00".join(
                [packet_id, *[f"{p}\x00{files[p]['sha256']}" for p in digest_inputs]]
            ).encode("utf-8")
        ).hexdigest()
        questions: list[dict[str, str]] = []
        if anchors:
            for entry in included:
                anchor = anchors.get(entry.fingerprint)
                if anchor is not None and anchor.get("anchor_status") != "resolved":
                    questions.append(
                        {
                            "fingerprint": entry.fingerprint,
                            "question": "no validated source anchor; confirm the finding location before review",
                        }
                    )
        packets.append(
            {
                "packet_version": PACKET_VERSION,
                "packet_id": packet_id,
                "packet_digest": packet_digest,
                "status": "partial" if truncated else "complete",
                "truncation_reasons": reasons,
                "target": {
                    "root_kind": "workspace",
                    "selected_files": digest_inputs,
                },
                "findings": [
                    {
                        "fingerprint": entry.fingerprint,
                        "rule_id": entry.rule_id,
                        "path": entry.path,
                        "line": entry.line,
                        "severity": str(
                            _field(_by_fingerprint(ordered, entry.fingerprint), "severity", "")
                        ),
                        "proof_level": str(
                            _field(_by_fingerprint(ordered, entry.fingerprint), "proof_level", "")
                        ),
                    }
                    for entry in included
                ],
                "files": [files[path] for path in digest_inputs],
                "source_bytes": used_bytes,
                "open_questions": questions,
                "token_estimate": used_bytes // 4,
                "token_estimate_note": "estimate only (bytes/4); not a measured tokenizer count",
            }
        )
    deferred_leftover = [entry for entry in ledger if entry.status == "selected"]
    for entry in deferred_leftover:
        entry.status = "deferred"
        entry.reasons.append(f"packet budget ({max_packets} packets) exhausted")
    identity_report = None
    identity_error = None
    try:
        scoped = sorted({path for packet in packets for path in packet["target"]["selected_files"]})
        absolute = [tree / Path(*relative.split("/")) for relative in scoped]
        snapshot = identity.snapshot_identity(
            tree,
            files=absolute,
            policy=policy or {},
            scanner_version=scanner_version,
            rules_identity=f"{rules_identity}:{identity.scanner_code_identity()}",
        )
        observed = {entry["path"]: entry["sha256"] for entry in snapshot["files"]}
        for packet in packets:
            for source in packet["files"]:
                if observed.get(source["path"]) != source["sha256"]:
                    raise ValueError("source changed while binding packet identity")
        for packet in packets:
            packet["target_digest"] = snapshot["target_digest"]
            packet["config_digest"] = snapshot["config_digest"]
            packet["target"]["commit"] = snapshot["commit"]
            packet["target"]["root_kind"] = snapshot["root_kind"]
        identity_report = {
            "target_digest": snapshot["target_digest"],
            "config_digest": snapshot["config_digest"],
        }
    except (OSError, ValueError) as exc:
        identity_error = str(exc)
        for packet in packets:
            packet["target_digest"] = None
            packet["config_digest"] = None
            packet["status"] = "partial"
            packet["truncation_reasons"].append("snapshot identity unavailable")
        for entry in ledger:
            if entry.status == "scheduled":
                entry.status = "failed"
                entry.reasons.append("snapshot identity unavailable")
    return {
        "packet_version": PACKET_VERSION,
        "packets": packets,
        "selection_accounting": [entry.as_dict() for entry in ledger],
        "counts": {
            "selected": len(ledger),
            "scheduled": sum(1 for entry in ledger if entry.status == "scheduled"),
            "failed": sum(1 for entry in ledger if entry.status == "failed"),
            "deferred": sum(1 for entry in ledger if entry.status == "deferred"),
            "packets": len(packets),
        },
        "identity": identity_report,
        "identity_error": identity_error,
        "reconcile_notes": [],
    }


def _by_fingerprint(findings: Iterable[Any], fingerprint: str) -> Any:
    for item in findings:
        if str(_field(item, "fingerprint")) == fingerprint:
            return item
    return {}


def reconcile(report: dict[str, Any], responses: list[dict[str, Any]]) -> dict[str, Any]:
    """Fold host-agent responses into the ledger without ever inventing completion."""
    packets = {packet["packet_id"]: packet for packet in report.get("packets", [])}
    ledger = {entry["fingerprint"]: entry for entry in report.get("selection_accounting", [])}
    notes: list[str] = list(report.get("reconcile_notes", []))
    decided: set[str] = set()
    for response in responses:
        packet_id = response.get("packet_id")
        if packet_id not in packets:
            notes.append(f"response for unknown packet {packet_id!r} ignored")
            continue
        if response.get("timed_out") or response.get("error"):
            reason = str(response.get("error") or "agent timed out")
            for entry in ledger.values():
                if entry.get("packet_id") == packet_id and entry.get("status") == "scheduled":
                    entry["status"] = "failed"
                    entry["reasons"].append(reason)
            notes.append(f"{packet_id}: marked scheduled items failed ({reason})")
            continue
        for decision in response.get("decided", []) or []:
            fingerprint = decision.get("fingerprint")
            if fingerprint not in ledger:
                notes.append(f"{packet_id}: unknown fingerprint {fingerprint!r} ignored")
                continue
            if ledger[fingerprint].get("packet_id") != packet_id:
                notes.append(
                    f"{packet_id}: fingerprint {fingerprint!r} belongs to "
                    f"{ledger[fingerprint].get('packet_id')!r}; kept with its own packet"
                )
                continue
            if fingerprint in decided:
                notes.append(f"{packet_id}: duplicate decision for {fingerprint!r} ignored")
                continue
            decided.add(fingerprint)
            if ledger[fingerprint].get("status") != "scheduled":
                notes.append(f"{packet_id}: fingerprint {fingerprint!r} was not scheduled; ignored")
                continue
            verdict = decision.get("verdict")
            if verdict == "completed":
                ledger[fingerprint]["status"] = "completed"
            elif verdict == "failed":
                ledger[fingerprint]["status"] = "failed"
                ledger[fingerprint]["reasons"].append(
                    str(decision.get("note") or "agent reported failure")
                )
            else:
                notes.append(
                    f"{packet_id}: fingerprint {fingerprint!r} has no usable verdict; left scheduled"
                )
    report["reconcile_notes"] = notes
    report["counts"] = {
        "selected": len(ledger),
        "scheduled": sum(1 for entry in ledger.values() if entry.get("status") == "scheduled"),
        "completed": sum(1 for entry in ledger.values() if entry.get("status") == "completed"),
        "failed": sum(1 for entry in ledger.values() if entry.get("status") == "failed"),
        "deferred": sum(1 for entry in ledger.values() if entry.get("status") == "deferred"),
        "packets": len(packets),
    }
    return report
