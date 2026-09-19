#!/usr/bin/env python3
"""Build a truthful inventory of ShipProof executable-rule assurance debt."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
SCANNER_SCRIPTS = ROOT / "skills" / "audit-production-readiness" / "scripts"
sys.path.insert(0, str(SCANNER_SCRIPTS))

from scan_repo import RULE_EXPLANATIONS, RULES, VERSION  # noqa: E402

MANIFEST_NAMES = (
    "rule_cases_secrets.json",
    "rule_cases_promoted.json",
    "rule_cases_v2.json",
)
LEGACY_CONTRACT_DIR = ROOT / "tests" / "rule-contracts"
BASELINE_PATH = ROOT / "tests" / "rule_assurance_legacy.json"
PRECISION_NEGATIVES_PATH = ROOT / "tests" / "precision_plan_negatives.json"
RULE_ID_PATTERN = re.compile(r"\bSP\d{3,}\b")
EXPLANATION_FIELDS = ("why", "attack", "false_positive", "test")
STRUCTURAL_MARKERS = re.compile(
    r"\b(?:def |async def |class |function |import |from |const |let |var |export |package )|"
    r"^\s*(?:if |for |while |try:|except )",
    re.MULTILINE,
)


def rule_number(rule_id: str) -> int:
    return int(rule_id.removeprefix("SP"))


def load_contracts() -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    contracts: dict[str, dict[str, Any]] = {}
    duplicate_ids: list[str] = []
    malformed_entries: list[str] = []
    manifest_paths = [ROOT / "tests" / name for name in MANIFEST_NAMES]
    if LEGACY_CONTRACT_DIR.is_dir():
        manifest_paths.extend(sorted(LEGACY_CONTRACT_DIR.glob("*.v2.json")))
    for manifest_path in manifest_paths:
        manifest_name = manifest_path.relative_to(ROOT / "tests").as_posix()
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in payload.get("rules", []):
            rule_id = entry.get("rule_id")
            if not isinstance(rule_id, str) or not RULE_ID_PATTERN.fullmatch(rule_id):
                malformed_entries.append(f"{manifest_name}:{rule_id!r}")
                continue
            if rule_id in contracts:
                duplicate_ids.append(rule_id)
                continue
            cases = entry.get("cases", entry)
            declared_counts = {
                polarity: len(cases.get(polarity, []))
                for polarity in ("positive", "negative", "adversarial")
            }
            placeholder_counts = {
                polarity: sum(
                    is_placeholder_case(case, polarity) for case in cases.get(polarity, [])
                )
                for polarity in ("positive", "negative", "adversarial")
            }
            contracts[rule_id] = {
                "manifest": manifest_name,
                "declared_counts": declared_counts,
                "placeholder_counts": placeholder_counts,
                "effective_counts": {
                    polarity: declared_counts[polarity] - placeholder_counts[polarity]
                    for polarity in declared_counts
                },
                "negative_cases": list(cases.get("negative", [])),
            }
    merge_precision_plan_negatives(contracts)
    return contracts, sorted(set(duplicate_ids), key=rule_number), malformed_entries


def merge_precision_plan_negatives(contracts: dict[str, dict[str, Any]]) -> None:
    if not PRECISION_NEGATIVES_PATH.is_file():
        return
    payload = json.loads(PRECISION_NEGATIVES_PATH.read_text(encoding="utf-8"))
    for entry in payload.get("rules", []):
        rule_id = entry.get("rule_id")
        contract = contracts.get(rule_id) if isinstance(rule_id, str) else None
        if contract is None:
            continue
        extra = {"path": entry.get("path", ""), "source": entry.get("source", "")}
        contract["negative_cases"].append(extra)
        contract["declared_counts"]["negative"] += 1
        if not is_placeholder_case(extra, "negative"):
            contract["effective_counts"]["negative"] += 1


def is_placeholder_case(case: Any, polarity: str) -> bool:
    if not isinstance(case, dict):
        return True
    source_fixture = case.get("source_fixture")
    if isinstance(source_fixture, dict):
        provider = source_fixture.get("provider")
        case_id = source_fixture.get("case")
        if provider == "secret-runtime" and case_id in {
            "positive_a",
            "positive_b",
            "negative_prefix_fragment",
            "negative_suffix_fragment",
            "adversarial_split_literal",
        }:
            return False
    content_hex = case.get("content_hex")
    if (
        isinstance(content_hex, str)
        and len(content_hex) % 2 == 0
        and re.fullmatch(r"[0-9a-f]*", content_hex)
    ):
        artifact_path = str(case.get("path", "")).casefold()
        empty_extension_evidence = polarity == "positive" and artifact_path.endswith(
            (".db", ".sqlite", ".sqlite3")
        )
        return not content_hex and not empty_extension_evidence
    source_hex = case.get("source_hex")
    if (
        isinstance(source_hex, str)
        and len(source_hex) % 2 == 0
        and re.fullmatch(r"[0-9a-f]*", source_hex)
    ):
        return not bool(bytes.fromhex(source_hex).strip())
    source = case.get("source")
    if source == "covered_by_suite" and polarity == "positive":
        return False
    if not isinstance(source, str):
        source_parts = case.get("source_parts")
        return not (
            isinstance(source_parts, list)
            and any(isinstance(part, str) and part.strip() for part in source_parts)
        )
    return bool(re.fullmatch(r"SAFE_(?:NEGATIVE|ADVERSARIAL)_SP\d{3,}", source))


def case_source_text(case: Any) -> str:
    if not isinstance(case, dict):
        return ""
    source_hex = case.get("source_hex")
    if (
        isinstance(source_hex, str)
        and len(source_hex) % 2 == 0
        and re.fullmatch(r"[0-9a-f]*", source_hex)
    ):
        try:
            return bytes.fromhex(source_hex).decode("utf-8", "replace")
        except ValueError:
            return ""
    source = case.get("source")
    if isinstance(source, str):
        return source
    parts = case.get("source_parts")
    if isinstance(parts, list):
        return "".join(part for part in parts if isinstance(part, str))
    return ""


def is_realistic_negative(case: Any) -> bool:
    if is_placeholder_case(case, "negative"):
        return False
    text = case_source_text(case).strip()
    if len(text) < 48:
        return False
    if text.count("\n") >= 2:
        return True
    return bool(STRUCTURAL_MARKERS.search(text))


def reference_files_by_rule() -> dict[str, list[str]]:
    references: defaultdict[str, set[str]] = defaultdict(set)
    excluded = {*MANIFEST_NAMES, BASELINE_PATH.name}
    candidates = [
        *ROOT.glob("tests/test_*.py"),
        *ROOT.glob("tests/node/*.mjs"),
        *ROOT.glob("fixtures/expected-*.json"),
    ]
    for path in candidates:
        if path.name in excluded:
            continue
        content = path.read_text(encoding="utf-8")
        relative_path = path.relative_to(ROOT).as_posix()
        for rule_id in RULE_ID_PATTERN.findall(content):
            references[rule_id].add(relative_path)
    return {rule_id: sorted(paths) for rule_id, paths in references.items()}


def minimum_counts(severity: str) -> dict[str, int]:
    return {
        "positive": 2 if severity in {"critical", "high"} else 1,
        "negative": 2,
        "adversarial": 1,
    }


def classify_rule(
    rule: Any,
    contract: dict[str, Any] | None,
    reference_files: dict[str, list[str]],
) -> dict[str, Any]:
    requirements = minimum_counts(rule.severity)
    counts = (
        contract["effective_counts"]
        if contract
        else {
            "positive": 0,
            "negative": 0,
            "adversarial": 0,
        }
    )
    missing_contract = [
        polarity for polarity, minimum in requirements.items() if counts[polarity] < minimum
    ]
    explanation = RULE_EXPLANATIONS.get(rule.rule_id, {})
    missing_metadata = []
    if not rule.cwe:
        missing_metadata.append("cwe")
    if not rule.remediation:
        missing_metadata.append("remediation")
    missing_metadata.extend(
        f"explanation.{field}" for field in EXPLANATION_FIELDS if not explanation.get(field)
    )
    if not contract:
        status = "uncontracted"
    elif missing_contract:
        status = "partial"
    else:
        status = "complete"
    negative_cases = contract["negative_cases"] if contract else []
    realistic_negatives = sum(1 for case in negative_cases if is_realistic_negative(case))
    near_miss_negatives = sum(
        1
        for case in negative_cases
        if not is_placeholder_case(case, "negative") and not is_realistic_negative(case)
    )
    if realistic_negatives:
        negative_quality = "realistic"
    elif near_miss_negatives:
        negative_quality = "near_miss_only"
    else:
        negative_quality = "none"
    return {
        "rule_id": rule.rule_id,
        "severity": rule.severity,
        "category": rule.category,
        "manifest": contract["manifest"] if contract else None,
        "status": status,
        "counts": counts,
        "declared_counts": contract["declared_counts"] if contract else counts,
        "placeholder_counts": contract["placeholder_counts"] if contract else counts,
        "minimum": requirements,
        "missing_contract": missing_contract,
        "missing_metadata": missing_metadata,
        "legacy_reference_files": reference_files.get(rule.rule_id, []),
        "negative_quality": negative_quality,
        "realistic_negatives": realistic_negatives,
        "near_miss_negatives": near_miss_negatives,
    }


def load_baseline() -> dict[str, Any] | None:
    if not BASELINE_PATH.is_file():
        return None
    return json.loads(BASELINE_PATH.read_text(encoding="utf-8"))


def build_report() -> dict[str, Any]:
    scanner_ids = {rule.rule_id for rule in RULES}
    contracts, duplicate_ids, malformed_entries = load_contracts()
    references = reference_files_by_rule()
    inventory = [
        classify_rule(rule, contracts.get(rule.rule_id), references)
        for rule in sorted(RULES, key=lambda item: rule_number(item.rule_id))
    ]
    status_counts = Counter(item["status"] for item in inventory)
    severity_status: dict[str, Counter[str]] = defaultdict(Counter)
    for item in inventory:
        severity_status[item["severity"]][item["status"]] += 1

    baseline = load_baseline()
    current_partial = {item["rule_id"] for item in inventory if item["status"] == "partial"}
    current_uncontracted = {
        item["rule_id"] for item in inventory if item["status"] == "uncontracted"
    }
    current_unrealistic = {
        item["rule_id"]
        for item in inventory
        if item["severity"] in {"critical", "high"} and item["negative_quality"] != "realistic"
    }
    baseline_partial = set(baseline.get("partial_contract_ids", [])) if baseline else set()
    baseline_uncontracted = set(baseline.get("uncontracted_ids", [])) if baseline else set()
    baseline_unrealistic = (
        set(baseline.get("high_critical_without_realistic_negative_ids", [])) if baseline else set()
    )
    current_debt = current_partial | current_uncontracted
    baseline_debt = baseline_partial | baseline_uncontracted
    metadata_debt = {item["rule_id"] for item in inventory if item["missing_metadata"]}
    gate = {
        "passed": False,
        "baseline_present": baseline is not None,
        "new_uncontracted_rule_ids": sorted(current_debt - baseline_debt, key=rule_number),
        "stale_baseline_rule_ids": sorted(baseline_debt - current_debt, key=rule_number),
        "misclassified_partial_rule_ids": sorted(
            baseline_partial ^ current_partial,
            key=rule_number,
        ),
        "misclassified_uncontracted_rule_ids": sorted(
            baseline_uncontracted ^ current_uncontracted,
            key=rule_number,
        ),
        "new_unrealistic_high_critical_ids": sorted(
            current_unrealistic - baseline_unrealistic, key=rule_number
        ),
        "stale_unrealistic_high_critical_ids": sorted(
            baseline_unrealistic - current_unrealistic, key=rule_number
        ),
        "manifest_rule_ids_not_executable": sorted(set(contracts) - scanner_ids, key=rule_number),
        "duplicate_manifest_rule_ids": duplicate_ids,
        "malformed_manifest_entries": malformed_entries,
        "metadata_debt_rule_ids": sorted(metadata_debt, key=rule_number),
    }
    gate["passed"] = bool(baseline) and not any(
        value for key, value in gate.items() if key not in {"passed", "baseline_present"}
    )
    return {
        "schema_version": "1.0",
        "tool": {
            "name": "ShipProof rule assurance",
            "version": VERSION,
        },
        "minimum_contract": {
            "all_rules": {"positive": 1, "negative": 2, "adversarial": 1},
            "critical_high": {"positive": 2, "negative": 2, "adversarial": 1},
        },
        "summary": {
            "executable_rules": len(inventory),
            "complete": status_counts["complete"],
            "partial": status_counts["partial"],
            "uncontracted": status_counts["uncontracted"],
            "metadata_debt": len(metadata_debt),
            "realistic_negatives": sum(
                1 for item in inventory if item["negative_quality"] == "realistic"
            ),
            "near_miss_only_negatives": sum(
                1 for item in inventory if item["negative_quality"] == "near_miss_only"
            ),
            "high_critical_without_realistic_negatives": len(current_unrealistic),
            "by_severity": {
                severity: {
                    status: counts[status] for status in ("complete", "partial", "uncontracted")
                }
                for severity, counts in sorted(severity_status.items())
            },
        },
        "gate": gate,
        "rules": inventory,
    }


def build_baseline(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "created_for_version": VERSION,
        "policy": (
            "Transitional debt only. New executable rules must satisfy the minimum contract; "
            "remove IDs as coverage is completed and never add IDs merely to make the gate pass."
        ),
        "partial_contract_ids": [
            item["rule_id"] for item in report["rules"] if item["status"] == "partial"
        ],
        "uncontracted_ids": [
            item["rule_id"] for item in report["rules"] if item["status"] == "uncontracted"
        ],
        "high_critical_without_realistic_negative_ids": [
            item["rule_id"]
            for item in report["rules"]
            if item["severity"] in {"critical", "high"} and item["negative_quality"] != "realistic"
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    debt = summary["partial"] + summary["uncontracted"]
    gate_name = "Zero-debt executable-rule gate" if debt == 0 else "Transitional new-rule gate"
    if debt == 0:
        gate_detail = (
            "Every executable rule meets the machine-readable polarity minimum. The checked-in "
            "empty debt baseline makes any future partial or uncontracted rule fail closed."
        )
    else:
        gate_detail = (
            "The gate does not relabel legacy references as fixture coverage. It blocks newly added "
            "debt, requires the checked-in debt baseline to shrink when a rule is completed, and "
            "reports every remaining ID in JSON."
        )
    lines = [
        "# ShipProof rule assurance inventory",
        "",
        f"Version: `{report['tool']['version']}`",
        "",
        "| Status | Rules | Meaning |",
        "| --- | ---: | --- |",
        f"| Complete | {summary['complete']} | Meets the current executable polarity minimum |",
        f"| Partial | {summary['partial']} | Has a manifest but misses at least one minimum |",
        f"| Uncontracted | {summary['uncontracted']} | No explicit machine-readable polarity manifest |",
        f"| Metadata debt | {summary['metadata_debt']} | Missing CWE, remediation, or explanation fields |",
        f"| Realistic negatives | {summary['realistic_negatives']} | At least one negative that looks like production code |",
        f"| Near-miss negatives only | {summary['near_miss_only_negatives']} | Token-boundary negatives without production-shaped silence |",
        f"| High/critical missing realistic negatives | {summary['high_critical_without_realistic_negatives']} | Shrink-only transitional debt |",
        "",
        f"{gate_name}: **{'PASS' if report['gate']['passed'] else 'FAIL'}**",
        "",
        gate_detail,
        "",
        "Placeholder-only `SAFE_NEGATIVE_*` and `SAFE_ADVERSARIAL_*` strings are reported but do not "
        "count as meaningful polarity evidence. Realistic negatives are production-shaped silent "
        "fixtures; the high/critical list in the debt baseline can only shrink.",
        "",
        "Maintainer source-checkout command: "
        "`python scripts/rule_assurance_report.py --format json --check`.",
        "Regenerate checked-in contracts with `python scripts/build_secret_rule_contracts.py`, "
        "`python scripts/build_legacy_pattern_contracts.py`, and "
        "`python scripts/build_legacy_structural_contracts.py`; baseline updates may only shrink debt.",
    ]
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("json", "markdown"), default="markdown")
    parser.add_argument("--check", action="store_true", help="exit 1 when the debt gate fails")
    baseline_group = parser.add_mutually_exclusive_group()
    baseline_group.add_argument(
        "--create-baseline",
        action="store_true",
        help="create the one-time reviewed legacy debt baseline; refuses to overwrite",
    )
    baseline_group.add_argument(
        "--update-baseline",
        action="store_true",
        help="shrink the reviewed debt baseline; refuses to add or reclassify debt",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = build_report()
    if args.create_baseline:
        if BASELINE_PATH.exists():
            print(f"refusing to overwrite {BASELINE_PATH}", file=sys.stderr)
            return 1
        BASELINE_PATH.write_text(
            json.dumps(build_baseline(report), indent=2) + "\n",
            encoding="utf-8",
        )
        report = build_report()
    if args.update_baseline:
        current = load_baseline()
        if current is None:
            print(f"missing baseline {BASELINE_PATH}", file=sys.stderr)
            return 1
        generated = build_baseline(report)
        old_debt = set(current.get("partial_contract_ids", [])) | set(
            current.get("uncontracted_ids", [])
        )
        new_debt = set(generated["partial_contract_ids"]) | set(generated["uncontracted_ids"])
        old_unrealistic = set(current.get("high_critical_without_realistic_negative_ids", []))
        new_unrealistic = set(generated["high_critical_without_realistic_negative_ids"])
        if not new_debt <= old_debt or not new_unrealistic <= old_unrealistic:
            added = sorted(
                (new_debt - old_debt) | (new_unrealistic - old_unrealistic), key=rule_number
            )
            print(
                "refusing to expand the reviewed debt baseline: " + ", ".join(added),
                file=sys.stderr,
            )
            return 1
        BASELINE_PATH.write_text(
            json.dumps(generated, indent=2) + "\n",
            encoding="utf-8",
        )
        report = build_report()
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render_markdown(report), end="")
    return 1 if args.check and not report["gate"]["passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
