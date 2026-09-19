#!/usr/bin/env python3
"""Advisory-only shadow run for fixture-ready research prototypes.

Prototypes stay out of RULES. This harness scores the batch-A polarity cases
and optional original fixtures, then writes a non-blocking shadow report.
Representative public repositories remain an external evidence requirement.

Usage:
  python scripts/eval-shadow-prototypes.py
  python scripts/eval-shadow-prototypes.py --json --write-report benchmarks/shadow-prototypes.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "research" / "promotion-batch-a.json"
FIXTURES = ROOT / "fixtures" / "shadow-prototypes"


def source_for(case: dict[str, Any]) -> str:
    return "".join(str(part) for part in case["source_parts"])


def compile_prototype(prototype: dict[str, Any]) -> re.Pattern[str]:
    flags = 0
    for name in prototype.get("flags") or []:
        flags |= getattr(re, str(name))
    return re.compile(str(prototype["pattern"]), flags)


def score_cases(pattern: re.Pattern[str], cases: dict[str, Any]) -> dict[str, Any]:
    counts = {
        "true_positive": 0,
        "false_positive": 0,
        "true_negative": 0,
        "false_negative": 0,
        "adversarial_held": 0,
        "adversarial_failed": 0,
    }
    mismatches: list[str] = []
    for polarity, _bucket in (
        ("positive", "true_positive"),
        ("negative", "true_negative"),
        ("adversarial", "adversarial_held"),
    ):
        for case in cases.get(polarity) or []:
            detected = bool(pattern.search(source_for(case)))
            expected = bool(case["expected"])
            if detected == expected:
                if polarity == "positive":
                    counts["true_positive"] += 1
                elif polarity == "negative":
                    counts["true_negative"] += 1
                else:
                    counts["adversarial_held"] += 1
            else:
                mismatches.append(f"{polarity}:{case['path']}")
                if polarity == "positive":
                    counts["false_negative"] += 1
                elif polarity == "negative":
                    counts["false_positive"] += 1
                else:
                    counts["adversarial_failed"] += 1
    return {**counts, "mismatches": mismatches}


def score_fixture_tree(pattern: re.Pattern[str], suffixes: set[str], root: Path) -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    files = 0
    if not root.is_dir():
        return {"files": 0, "hits": []}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        files += 1
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            hits.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "line": line,
                    "tier": "advisory",
                }
            )
    return {"files": files, "hits": hits}


def evaluate() -> dict[str, Any]:
    batch = json.loads(BATCH.read_text(encoding="utf-8"))
    ready = [
        item
        for item in batch.get("candidates") or []
        if item.get("batch_status") == "fixture_ready"
    ]
    results = []
    for item in ready:
        prototype = item["prototype"]
        pattern = compile_prototype(prototype)
        polarity = score_cases(pattern, item["cases"])
        fixture_root = FIXTURES / str(item["candidate_id"]).lower()
        suffixes = {suffix.lower() for suffix in prototype.get("suffixes") or []}
        fixtures = score_fixture_tree(pattern, suffixes, fixture_root)
        results.append(
            {
                "candidate_id": item["candidate_id"],
                "status": "advisory_only",
                "promoted": False,
                "engine": prototype.get("engine"),
                "polarity": {key: value for key, value in polarity.items() if key != "mismatches"},
                "polarity_mismatches": polarity["mismatches"],
                "synthetic_fixtures": fixtures,
            }
        )
    return {
        "schema_version": "1.0",
        "tool": {"name": "ShipProof", "command": "eval-shadow-prototypes"},
        "verdict": "PASS_WITH_EVIDENCE",
        "limitations": [
            "Shadow prototypes are advisory and are not executable RULES.",
            "Polarity cases are synthetic. They are not representative-repository precision.",
            "Residual P2A-EXT evidence still requires license-reviewed pinned public repositories.",
        ],
        "promoted_ids": [],
        "candidates": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--write-report", type=Path)
    arguments = parser.parse_args()
    try:
        payload = evaluate()
    except (OSError, ValueError, TypeError, json.JSONDecodeError, re.error) as exc:
        print(f"shadow prototypes: {exc}", file=sys.stderr)
        return 2
    mismatches = [
        item["candidate_id"] for item in payload["candidates"] if item["polarity_mismatches"]
    ]
    if mismatches:
        payload["verdict"] = "INVALID_EVIDENCE"
    if arguments.write_report is not None:
        path = arguments.write_report
        if not path.is_absolute():
            path = ROOT / path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if arguments.json:
        print(json.dumps(payload, indent=2))
    else:
        for item in payload["candidates"]:
            polarity = item["polarity"]
            print(
                f"{item['candidate_id']} advisory promoted=false "
                f"TP={polarity['true_positive']} TN={polarity['true_negative']} "
                f"fixture_hits={len(item['synthetic_fixtures']['hits'])}"
            )
        if mismatches:
            print(f"UNAVAILABLE: polarity mismatches for {mismatches}")
    return 2 if mismatches else 0


if __name__ == "__main__":
    sys.exit(main())
