#!/usr/bin/env python3
"""Opt-in Skill/MCP capability inventory. Not a blocking scanner rule.

Walks SKILL.md files and common MCP config names, splits declared vs
observed-static vs unknown, and redacts credential-shaped values. Absence of a
capability is unknown, not safe.

Usage:
  python scripts/ai_inventory.py [path] [--json]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_FILES = 256
MAX_FILE_BYTES = 256 * 1024
SKILL_NAME = "SKILL.md"
MCP_NAMES = frozenset(
    {
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "mcp_config.json",
    }
)
SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|token|secret|password|authorization|credential|private[_-]?key)$",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(r"(?i)(?:sk-|ghp_|github_pat_|xox[baprs]-|Bearer\s+)[A-Za-z0-9._\-]+")
OBSERVED_PATTERNS = (
    ("network", re.compile(r"\b(?:fetch|axios|httpx|requests|urllib|subprocess|os\.system)\b")),
    ("filesystem", re.compile(r"\b(?:readFile|writeFile|open\s*\(|Path\s*\(|fs\.)")),
    ("process", re.compile(r"\b(?:spawn|exec|subprocess|child_process)\b")),
    ("credential_access", re.compile(r"\b(?:os\.environ|process\.env|getenv|SecretStr)\b")),
)
SKIP_DIRS = frozenset(
    {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}
)


def redact_text(value: str) -> str:
    return SECRET_VALUE_RE.sub("[REDACTED]", value)


def redact_mapping(payload: object) -> object:
    if isinstance(payload, dict):
        redacted: dict[str, object] = {}
        for key, value in payload.items():
            if isinstance(key, str) and SECRET_KEY_RE.search(key) and isinstance(value, str):
                redacted[key] = "[REDACTED]"
            else:
                redacted[str(key)] = redact_mapping(value)
        return redacted
    if isinstance(payload, list):
        return [redact_mapping(item) for item in payload]
    if isinstance(payload, str):
        return redact_text(payload)
    return payload


def parse_front_matter(text: str) -> dict[str, str]:
    if not text.startswith("---"):
        return {}
    end = text.find("\n---", 3)
    if end < 0:
        return {}
    declared: dict[str, str] = {}
    for line in text[3:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in {"name", "description"}:
            declared[key] = redact_text(value.strip().strip("'\""))
    return declared


def iter_inventory_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        name = path.name
        if name == SKILL_NAME or name in MCP_NAMES:
            files.append(path)
        if len(files) >= MAX_FILES:
            break
    files.sort(key=lambda item: item.relative_to(root).as_posix())
    return files


def observed_from_text(text: str) -> list[str]:
    found = []
    for label, pattern in OBSERVED_PATTERNS:
        if pattern.search(text) and label not in found:
            found.append(label)
    return found


def inspect_file(root: Path, path: Path) -> dict[str, Any]:
    relative = path.relative_to(root).as_posix()
    record: dict[str, Any] = {
        "path": relative,
        "kind": "skill" if path.name == SKILL_NAME else "mcp_config",
        "declared": {},
        "observed_static": [],
        "unknown": [],
        "status": "ok",
    }
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            record["status"] = "unknown"
            record["unknown"].append("oversized")
            return record
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        record["status"] = "unknown"
        record["unknown"].append("unreadable")
        return record
    record["observed_static"] = observed_from_text(text)
    if path.name == SKILL_NAME:
        record["declared"] = parse_front_matter(text)
        if not record["declared"]:
            record["unknown"].append("missing_front_matter")
        return record
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        record["status"] = "unknown"
        record["unknown"].append("invalid_json")
        return record
    servers = payload.get("mcpServers") if isinstance(payload, dict) else None
    declared: dict[str, object] = {}
    if isinstance(servers, dict):
        declared["servers"] = sorted(str(name) for name in servers)
        commands = []
        for spec in servers.values():
            if isinstance(spec, dict) and isinstance(spec.get("command"), str):
                commands.append(spec["command"])
        if commands:
            declared["commands"] = commands
    record["declared"] = (
        redact_mapping(declared)
        if declared
        else redact_mapping({"keys": sorted(payload) if isinstance(payload, dict) else []})
    )
    return record


def inventory(root: Path) -> dict[str, Any]:
    files = iter_inventory_files(root)
    components = [inspect_file(root, path) for path in files]
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "command": "ai-inventory"},
        "verdict": "PASS_WITH_EVIDENCE",
        "root": str(root.resolve()),
        "limitations": [
            "Inventory is static and opt-in. Missing evidence is unknown, not safe.",
            "Credential values are redacted. Environment reads and ordinary HTTP calls are not exfiltration.",
            "This report is not a blocking scanner rule and is not merged into scan verdicts.",
        ],
        "summary": {
            "components": len(components),
            "unknown": sum(1 for item in components if item["unknown"]),
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    root = arguments.root.resolve()
    if not root.is_dir():
        print(f"ai inventory: not a directory: {root}", file=sys.stderr)
        return 2
    payload = inventory(root)
    if arguments.json:
        print(json.dumps(payload, indent=2))
    else:
        print(
            f"components={payload['summary']['components']} unknown={payload['summary']['unknown']}"
        )
        for item in payload["components"]:
            print(
                f"{item['kind']:11} {item['path']} declared={item['declared']} unknown={item['unknown']}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
