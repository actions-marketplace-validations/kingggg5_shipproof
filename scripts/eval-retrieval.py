#!/usr/bin/env python3
"""Score the lexical rule-search baseline on the fixed question set.

Offline, dependency-free. Reports Recall@5 and MRR overall and split by
language (English/Thai) and by development/holdout assignment, plus mean/p95
query latency. Holdout questions exist to judge relevance; tuning ranking on
them promotes the holdout to development.

Exit codes: 0 report produced, 2 malformed input.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "skills" / "audit-production-readiness" / "scripts"))

import rule_search  # noqa: E402
from scan_repo import RULES  # noqa: E402

EVAL_PATH = ROOT / "benchmarks" / "retrieval-eval.jsonl"
TOP_K = 5


def load_questions(path: Path) -> list[dict]:
    questions = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path.name}:{line_number}: invalid JSON") from exc
        if not isinstance(item, dict):
            raise ValueError(f"{path.name}:{line_number}: question must be an object")
        for field in ("id", "lang", "split", "text", "relevant"):
            if field not in item:
                raise ValueError(f"{path.name}:{line_number}: missing {field}")
        if item["lang"] not in {"en", "th"} or item["split"] not in {
            "development",
            "holdout",
        }:
            raise ValueError(f"{path.name}:{line_number}: bad lang/split")
        if not isinstance(item["relevant"], list) or not item["relevant"]:
            raise ValueError(f"{path.name}:{line_number}: relevant must be non-empty")
        questions.append(item)
    return questions


def nearest_rank_percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = min(len(ordered) - 1, max(0, math.ceil(percentile / 100 * len(ordered)) - 1))
    return ordered[position]


def score(index: rule_search.SearchIndex, questions: list[dict]) -> dict:
    latencies: list[float] = []
    per_question = []
    for question in questions:
        started = time.perf_counter()
        answer = rule_search.search(index, question["text"], top_k=TOP_K)
        latencies.append((time.perf_counter() - started) * 1000)
        ranked = [
            result.get("rule_id") or result.get("candidate_id") for result in answer["results"]
        ]
        relevant = set(question["relevant"])
        hits = [position for position, rule_id in enumerate(ranked, 1) if rule_id in relevant]
        rank = min(hits) if hits else None
        per_question.append(
            {
                "id": question["id"],
                "lang": question["lang"],
                "split": question["split"],
                "rank": rank,
                "recall_at_5": len(set(ranked[:TOP_K]) & relevant) / len(relevant),
                "hit_at_5": rank is not None and rank <= TOP_K,
                "reciprocal_rank": (1 / rank) if rank else 0.0,
            }
        )

    def aggregate(rows: list[dict]) -> dict:
        if not rows:
            return {"questions": 0}
        recall = sum(row["recall_at_5"] for row in rows) / len(rows)
        mrr = sum(row["reciprocal_rank"] for row in rows) / len(rows)
        return {
            "questions": len(rows),
            f"recall_at_{TOP_K}": round(recall, 4),
            f"hit_rate_at_{TOP_K}": round(sum(row["hit_at_5"] for row in rows) / len(rows), 4),
            "mrr": round(mrr, 4),
        }

    return {
        "overall": aggregate(per_question),
        "en": aggregate([row for row in per_question if row["lang"] == "en"]),
        "th": aggregate([row for row in per_question if row["lang"] == "th"]),
        "development": aggregate([row for row in per_question if row["split"] == "development"]),
        "holdout": aggregate([row for row in per_question if row["split"] == "holdout"]),
        "latency_ms_mean": round(sum(latencies) / len(latencies), 3) if latencies else 0.0,
        "latency_ms_p95": round(nearest_rank_percentile(latencies, 95), 3),
        "per_question": per_question,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--eval", type=Path, default=EVAL_PATH)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    try:
        questions = load_questions(arguments.eval)
        index = rule_search.build_executable_index(
            list(RULES), lambda rule_id: next(r.remediation for r in RULES if r.rule_id == rule_id)
        )
        report = {
            "search_version": rule_search.SEARCH_VERSION,
            "top_k": TOP_K,
            "evaluation_status": "development-only: former holdout was consulted during model selection; refresh before acceptance",
            "index": {"kind": "executable", "documents": len(index.documents)},
            "results": score(index, questions),
        }
    except (OSError, ValueError) as exc:
        print(f"retrieval eval: {exc}", file=sys.stderr)
        return 2
    if arguments.json:
        print(json.dumps(report, indent=2))
    else:
        for name in ("overall", "en", "th", "development", "holdout"):
            print(f"{name:12} {report['results'][name]}")
        print(
            f"latency_ms mean={report['results']['latency_ms_mean']} "
            f"p95={report['results']['latency_ms_p95']}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
