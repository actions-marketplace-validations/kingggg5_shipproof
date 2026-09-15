#!/usr/bin/env python3
"""Offline head-to-head harness comparing ShipProof with a user-supplied Semgrep run.

Fairness rules baked into the protocol:
- Both tools scan the identical local corpus on the same machine, measured
  end-to-end (process start to report) with the median of N repeats.
- ShipProof runs its own scanner exactly as shipped (no rule cherry-picking).
- Semgrep runs only with rule files the caller supplies via --semgrep-config.
  ShipProof never bundles, downloads, or copies third-party rules, and the
  harness performs no network access.
- When a label file marks vulnerable files and sink lines per corpus, both
  tools are scored with the same file-level and line-level precision/recall.
  Line scoring uses path and line only so a caller-supplied comparison
  scanner does not need ShipProof rule IDs. No general superiority claim
  is made: results describe exactly these corpora, configs, and machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCANNER = ROOT / "skills" / "audit-production-readiness" / "scripts" / "scan_repo.py"
DEFAULT_LABELS = ROOT / "benchmarks" / "head-to-head-labels.json"


def sha256_tree(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(
        (
            candidate
            for candidate in root.rglob("*")
            if candidate.is_symlink() or candidate.is_file()
        ),
        key=lambda candidate: candidate.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        if path.is_symlink():
            digest.update(b"SYMLINK\0")
            digest.update(os.readlink(path).encode("utf-8", errors="surrogateescape"))
        else:
            digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="+", type=Path, help="Repository directories to scan")
    parser.add_argument(
        "--semgrep-config",
        action="append",
        default=[],
        help="Rule file for Semgrep (repeatable); without it the Semgrep leg is skipped",
    )
    parser.add_argument(
        "--labels",
        type=Path,
        default=DEFAULT_LABELS,
        help="JSON mapping corpus directory name to labeled vulnerable files",
    )
    parser.add_argument("--repeat", type=int, default=3, help="Timed runs per tool (median kept)")
    parser.add_argument("--min-file-precision", type=float)
    parser.add_argument("--min-file-recall", type=float)
    parser.add_argument("--min-line-precision", type=float)
    parser.add_argument("--min-line-recall", type=float)
    parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="markdown",
    )
    return parser.parse_args(argv)


def timed_run(command: list[str], cwd: Path) -> tuple[float, subprocess.CompletedProcess[str]]:
    started = time.perf_counter()
    process = subprocess.run(  # noqa: S603 - fixed argv, shell disabled by design
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        shell=False,
    )
    elapsed = time.perf_counter() - started
    return elapsed, process


def _record_hits(
    findings: Sequence[dict[str, object]],
    corpus_name: str,
    *,
    line_from: str,
) -> tuple[set[tuple[str, str]], set[tuple[str, int, str]]]:
    prefix = f"{corpus_name}/"
    file_rule_hits: set[tuple[str, str]] = set()
    line_hits: set[tuple[str, int, str]] = set()
    for finding in findings:
        path = str(finding.get("path") or "").removeprefix(prefix).replace("\\", "/")
        rule_id = str(finding.get("rule_id") or finding.get("check_id") or "unknown")
        if not path:
            continue
        file_rule_hits.add((path, rule_id))
        line_value = finding.get("line")
        if line_value is None and line_from == "semgrep":
            start = finding.get("start")
            if isinstance(start, dict):
                line_value = start.get("line")
        if isinstance(line_value, int) and line_value >= 1:
            line_hits.add((path, line_value, rule_id))
    return file_rule_hits, line_hits


def run_shipproof(corpus: Path, repeat: int) -> dict[str, object]:
    durations: list[float] = []
    file_rule_hits: set[tuple[str, str]] | None = None
    line_hits: set[tuple[str, int, str]] | None = None
    files_scanned: int | None = None
    for _ in range(repeat):
        elapsed, process = timed_run(
            [
                sys.executable,
                str(SCANNER),
                str(corpus),
                "--format",
                "json",
                "--fail-on",
                "none",
                # The full capability as shipped: include the interprocedural
                # taint engine so the comparison covers L2 evidence too.
                "--cross-file",
            ],
            corpus.parent,
        )
        if process.returncode not in (0, 1):
            raise RuntimeError(f"shipproof exited {process.returncode}: {process.stderr[:400]}")
        durations.append(elapsed)
        report = json.loads(process.stdout)
        current_files_scanned = int(report["summary"]["files_scanned"])
        if files_scanned is not None and current_files_scanned != files_scanned:
            raise RuntimeError("shipproof file count changed between repeated runs")
        files_scanned = current_files_scanned
        current_hits, current_lines = _record_hits(
            report["findings"], corpus.name, line_from="shipproof"
        )
        if file_rule_hits is not None and current_hits != file_rule_hits:
            raise RuntimeError("shipproof findings changed between repeated runs")
        if line_hits is not None and current_lines != line_hits:
            raise RuntimeError("shipproof finding lines changed between repeated runs")
        file_rule_hits = current_hits
        line_hits = current_lines
    if file_rule_hits is None or line_hits is None:
        raise RuntimeError("shipproof benchmark did not execute")
    files_flagged = sorted({path for path, _ in file_rule_hits})
    return {
        "tool": "shipproof",
        "median_seconds": round(statistics.median(durations), 3),
        "samples_seconds": [round(value, 3) for value in durations],
        "files_scanned": files_scanned,
        "findings": len(file_rule_hits),
        "files_flagged": files_flagged,
        "rule_hits": sorted(f"{path}:{rule}" for path, rule in file_rule_hits),
        "line_hits": [
            {"path": path, "line": line, "rule_id": rule_id}
            for path, line, rule_id in sorted(line_hits)
        ],
    }


def build_semgrep_command(corpus: Path, configs: Sequence[str]) -> list[str]:
    command = ["semgrep", "scan", "--json", "--disable-nosem"]
    for config in configs:
        command.extend(["--config", str(Path(config).resolve())])
    command.append(corpus.name)
    return command


def run_semgrep(corpus: Path, configs: Sequence[str], repeat: int) -> dict[str, object]:
    durations: list[float] = []
    file_rule_hits: set[tuple[str, str]] | None = None
    line_hits: set[tuple[str, int, str]] | None = None
    command = build_semgrep_command(corpus, configs)
    for _ in range(repeat):
        elapsed, process = timed_run(command, corpus.parent)
        if process.returncode not in (0, 1):
            raise RuntimeError(f"semgrep exited {process.returncode}: {process.stderr[:400]}")
        durations.append(elapsed)
        payload = json.loads(process.stdout)
        current_hits, current_lines = _record_hits(
            list(payload.get("results") or []), corpus.name, line_from="semgrep"
        )
        if file_rule_hits is not None and current_hits != file_rule_hits:
            raise RuntimeError("semgrep findings changed between repeated runs")
        if line_hits is not None and current_lines != line_hits:
            raise RuntimeError("semgrep finding lines changed between repeated runs")
        file_rule_hits = current_hits
        line_hits = current_lines
    if file_rule_hits is None or line_hits is None:
        raise RuntimeError("semgrep benchmark did not execute")
    files_flagged = sorted({path for path, _ in file_rule_hits})
    return {
        "tool": "semgrep",
        "median_seconds": round(statistics.median(durations), 3),
        "samples_seconds": [round(value, 3) for value in durations],
        "findings": len(file_rule_hits),
        "files_flagged": files_flagged,
        "rule_hits": sorted(f"{path}:{rule}" for path, rule in file_rule_hits),
        "line_hits": [
            {"path": path, "line": line, "rule_id": rule_id}
            for path, line, rule_id in sorted(line_hits)
        ],
    }


def compute_file_metrics(
    files_flagged: Sequence[str],
    labeled_files: Sequence[str],
    total_files: int | None = None,
    context_only_files: Sequence[str] = (),
) -> dict[str, object]:
    """File-level scoring: identical labels for every tool, no rule mapping needed."""
    context_only = set(context_only_files)
    flagged = set(files_flagged) - context_only
    labeled = set(labeled_files)
    if labeled & context_only:
        raise ValueError("positive and context-only labels must be disjoint")
    true_positives = len(flagged & labeled)
    false_positives = len(flagged - labeled)
    false_negatives = len(labeled - flagged)
    observed_files = len(flagged | labeled)
    universe_size = observed_files if total_files is None else total_files - len(context_only)
    if universe_size < observed_files:
        raise ValueError("total_files is smaller than the observed label/finding universe")
    true_negatives = universe_size - true_positives - false_positives - false_negatives
    precision = true_positives / (true_positives + false_positives) if flagged else None
    recall = true_positives / (true_positives + false_negatives) if labeled else None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
    return {
        "files_flagged": len(flagged),
        "labeled_files": len(labeled),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "true_negatives": true_negatives,
        "total_files": universe_size,
        "context_only_files": len(context_only),
        "file_precision": round(precision, 3) if precision is not None else None,
        "file_recall": round(recall, 3) if recall is not None else None,
        "file_f1": round(f1, 3) if f1 is not None else None,
    }


def compute_line_metrics(
    line_hits: Sequence[dict[str, object]],
    labeled_lines: Sequence[dict[str, object]],
    context_only_files: Sequence[str] = (),
) -> dict[str, object]:
    """Line-level scoring uses path and line only so tools need not share rule IDs."""
    context_only = set(context_only_files)
    flagged: set[tuple[str, int]] = set()
    for hit in line_hits:
        path = str(hit.get("path") or "")
        line = hit.get("line")
        if path and path not in context_only and isinstance(line, int) and line >= 1:
            flagged.add((path, line))
    labeled: set[tuple[str, int]] = set()
    for item in labeled_lines:
        path = str(item.get("path") or "")
        line = item.get("line")
        if path in context_only:
            raise ValueError("positive line labels must not use context-only files")
        if not path or not isinstance(line, int) or line < 1:
            raise ValueError("positive line labels require path and a 1-indexed line")
        labeled.add((path, line))
    true_positives = len(flagged & labeled)
    false_positives = len(flagged - labeled)
    false_negatives = len(labeled - flagged)
    precision = true_positives / (true_positives + false_positives) if flagged else None
    recall = true_positives / (true_positives + false_negatives) if labeled else None
    if precision is not None and recall is not None and precision + recall > 0:
        f1 = 2 * precision * recall / (precision + recall)
    else:
        f1 = None
    return {
        "lines_flagged": len(flagged),
        "labeled_lines": len(labeled),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "line_precision": round(precision, 3) if precision is not None else None,
        "line_recall": round(recall, 3) if recall is not None else None,
        "line_f1": round(f1, 3) if f1 is not None else None,
    }


def _parse_positive_lines(
    corpus: Path, entry: dict[str, object], positive_files: list[str], context_only: list[str]
) -> list[dict[str, object]]:
    raw_lines = entry.get("positive_lines")
    if raw_lines is None:
        return []
    if not isinstance(raw_lines, list):
        raise ValueError(f"{corpus.name}: positive_lines must be an array")
    parsed: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    for item in raw_lines:
        if not isinstance(item, dict):
            raise ValueError(f"{corpus.name}: each positive line must be an object")
        path = item.get("path")
        line = item.get("line")
        rule_id = item.get("rule_id")
        extra = set(item) - {"path", "line", "rule_id"}
        if extra:
            raise ValueError(f"{corpus.name}: unknown positive-line fields {sorted(extra)}")
        if not isinstance(path, str) or not path:
            raise ValueError(f"{corpus.name}: positive line path must be a non-empty string")
        relative = Path(path)
        if relative.is_absolute() or ".." in relative.parts or not (corpus / relative).is_file():
            raise ValueError(f"{corpus.name}: invalid or missing labeled file {path}")
        if path in context_only:
            raise ValueError(f"{corpus.name}: {path} cannot be both a sink line and context-only")
        if path not in positive_files:
            raise ValueError(f"{corpus.name}: sink line {path} is not in positive_files")
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            raise ValueError(f"{corpus.name}: {path} line must be a 1-indexed integer")
        if rule_id is not None and (not isinstance(rule_id, str) or not rule_id):
            raise ValueError(f"{corpus.name}: rule_id must be a non-empty string when present")
        key = (path, line)
        if key in seen:
            raise ValueError(f"{corpus.name}: duplicate sink line {path}:{line}")
        seen.add(key)
        record: dict[str, object] = {"path": path, "line": line}
        if isinstance(rule_id, str):
            record["rule_id"] = rule_id
        parsed.append(record)
    return parsed


def load_labels(labels_path: Path, corpora: Sequence[Path]) -> dict[str, dict[str, object]]:
    if not labels_path.is_file():
        raise FileNotFoundError(f"label file does not exist: {labels_path}")
    payload = json.loads(labels_path.read_text(encoding="utf-8"))
    schema_version = payload.get("schema_version")
    if schema_version not in {2, 3} or not isinstance(payload.get("corpora"), dict):
        raise ValueError("label file must use schema_version 2 or 3 with a corpora object")
    labels: dict[str, dict[str, object]] = {}
    for corpus in corpora:
        entry = payload["corpora"].get(corpus.name)
        if not isinstance(entry, dict):
            raise ValueError(f"label file is missing corpus {corpus.name}")
        positive = entry.get("positive_files")
        context_only = entry.get("context_only_files")
        if not isinstance(positive, list) or not isinstance(context_only, list):
            raise ValueError(f"{corpus.name}: labels must be arrays")
        if any(not isinstance(value, str) or not value for value in [*positive, *context_only]):
            raise ValueError(f"{corpus.name}: labels must be non-empty strings")
        if set(positive) & set(context_only):
            raise ValueError(f"{corpus.name}: positive and context-only labels overlap")
        for relative_path in [*positive, *context_only]:
            path = Path(relative_path)
            if path.is_absolute() or ".." in path.parts or not (corpus / path).is_file():
                raise ValueError(f"{corpus.name}: invalid or missing labeled file {relative_path}")
        positive_files = sorted(set(positive))
        context_only_files = sorted(set(context_only))
        if schema_version == 3:
            if "positive_lines" not in entry:
                raise ValueError(f"{corpus.name}: schema_version 3 requires positive_lines")
            positive_lines = _parse_positive_lines(
                corpus, entry, positive_files, context_only_files
            )
        else:
            if "positive_lines" in entry:
                raise ValueError(f"{corpus.name}: schema_version 2 cannot include positive_lines")
            positive_lines = []
        labels[corpus.name] = {
            "positive_files": positive_files,
            "context_only_files": context_only_files,
            "positive_lines": positive_lines,
        }
    return labels


def _metric_cell(value: object) -> str:
    return "n/a" if value is None else str(value)


def score_tool(
    result: dict[str, object],
    corpus_labels: dict[str, object],
    total_files: int,
) -> dict[str, object]:
    file_metrics = compute_file_metrics(
        list(result["files_flagged"]),
        list(corpus_labels["positive_files"]),
        total_files,
        list(corpus_labels["context_only_files"]),
    )
    line_metrics = compute_line_metrics(
        list(result.get("line_hits") or []),
        list(corpus_labels["positive_lines"]),
        list(corpus_labels["context_only_files"]),
    )
    return {"file": file_metrics, "line": line_metrics}


def render_markdown(results: Sequence[dict[str, object]]) -> str:
    lines = [
        "# ShipProof head-to-head results",
        "",
        "Same corpora, same machine, median end-to-end wall time per tool.",
        "File-level and line-level scoring use the shared label file; they",
        "describe these corpora and configs only, not general superiority.",
        "",
        "| Tool | Corpus | Median seconds | Findings | TP | FP | FN | TN | Precision | Recall | F1 |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for entry in results:
        metrics = entry["metrics"]["file"] if "file" in entry["metrics"] else entry["metrics"]
        lines.append(
            "| {tool} | {corpus} | {seconds} | {findings} | {tp} | {fp} | {fn} | {tn} | "
            "{precision} | {recall} | {f1} |".format(
                tool=entry["tool"],
                corpus=entry["corpus"],
                seconds=entry["result"]["median_seconds"],
                findings=entry["result"]["findings"],
                tp=metrics["true_positives"],
                fp=metrics["false_positives"],
                fn=metrics["false_negatives"],
                tn=metrics["true_negatives"],
                precision=_metric_cell(metrics["file_precision"]),
                recall=_metric_cell(metrics["file_recall"]),
                f1=_metric_cell(metrics["file_f1"]),
            )
        )
    if any(
        isinstance(entry.get("metrics"), dict) and "line" in entry["metrics"] for entry in results
    ):
        lines.extend(
            [
                "",
                "Line-level sink scoring (path and line only; context-only files ignored):",
                "",
                "| Tool | Corpus | Line TP | Line FP | Line FN | Line precision | Line recall | Line F1 |",
                "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for entry in results:
            line_metrics = (
                entry["metrics"].get("line") if isinstance(entry["metrics"], dict) else None
            )
            if not isinstance(line_metrics, dict):
                continue
            lines.append(
                "| {tool} | {corpus} | {tp} | {fp} | {fn} | {precision} | {recall} | {f1} |".format(
                    tool=entry["tool"],
                    corpus=entry["corpus"],
                    tp=line_metrics["true_positives"],
                    fp=line_metrics["false_positives"],
                    fn=line_metrics["false_negatives"],
                    precision=_metric_cell(line_metrics["line_precision"]),
                    recall=_metric_cell(line_metrics["line_recall"]),
                    f1=_metric_cell(line_metrics["line_f1"]),
                )
            )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parse_arguments(argv)
    corpora = [corpus.resolve() for corpus in arguments.corpora]
    for corpus in corpora:
        if not corpus.is_dir():
            print(f"head-to-head: not a directory: {corpus}", file=sys.stderr)
            return 2
    if arguments.repeat < 1:
        print("head-to-head: --repeat must be >= 1", file=sys.stderr)
        return 2
    for name, value in (
        ("--min-file-precision", arguments.min_file_precision),
        ("--min-file-recall", arguments.min_file_recall),
        ("--min-line-precision", arguments.min_line_precision),
        ("--min-line-recall", arguments.min_line_recall),
    ):
        if value is not None and not 0 <= value <= 1:
            print(f"head-to-head: {name} must be from 0 through 1", file=sys.stderr)
            return 2
    configs = [str(Path(value).resolve()) for value in arguments.semgrep_config]
    for config in configs:
        if not Path(config).is_file():
            print(f"head-to-head: Semgrep config is not a file: {config}", file=sys.stderr)
            return 2
    try:
        labels = load_labels(arguments.labels.resolve(), corpora)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"head-to-head: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, object]] = []
    try:
        for corpus in corpora:
            shipproof_result = run_shipproof(corpus, arguments.repeat)
            total_files = int(shipproof_result["files_scanned"])
            corpus_labels = labels[corpus.name]
            results.append(
                {
                    "tool": "shipproof",
                    "corpus": corpus.name,
                    "result": shipproof_result,
                    "metrics": score_tool(shipproof_result, corpus_labels, total_files),
                }
            )
            if configs:
                semgrep_result = run_semgrep(corpus, configs, arguments.repeat)
                results.append(
                    {
                        "tool": "semgrep",
                        "corpus": corpus.name,
                        "result": semgrep_result,
                        "metrics": score_tool(semgrep_result, corpus_labels, total_files),
                    }
                )
    except (OSError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"head-to-head: unavailable evidence: {exc}", file=sys.stderr)
        return 2

    threshold_failures: list[str] = []
    for entry in results:
        if entry["tool"] != "shipproof":
            continue
        file_metrics = entry["metrics"]["file"]
        line_metrics = entry["metrics"]["line"]
        precision = file_metrics["file_precision"]
        recall = file_metrics["file_recall"]
        if (
            arguments.min_file_precision is not None
            and precision is not None
            and precision < arguments.min_file_precision
        ):
            threshold_failures.append(f"{entry['corpus']}:file-precision={precision}")
        if (
            arguments.min_file_recall is not None
            and recall is not None
            and recall < arguments.min_file_recall
        ):
            threshold_failures.append(f"{entry['corpus']}:file-recall={recall}")
        line_precision = line_metrics["line_precision"]
        line_recall = line_metrics["line_recall"]
        if (
            arguments.min_line_precision is not None
            and line_precision is not None
            and line_precision < arguments.min_line_precision
        ):
            threshold_failures.append(f"{entry['corpus']}:line-precision={line_precision}")
        if (
            arguments.min_line_recall is not None
            and line_recall is not None
            and line_recall < arguments.min_line_recall
        ):
            threshold_failures.append(f"{entry['corpus']}:line-recall={line_recall}")

    if arguments.format == "json":
        print(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "tool": {"name": "ShipProof", "command": "head-to-head"},
                    "environment": {
                        "platform": platform.platform(),
                        "python": platform.python_version(),
                        "repeat": arguments.repeat,
                    },
                    "labels_sha256": hashlib.sha256(
                        arguments.labels.resolve().read_bytes()
                    ).hexdigest(),
                    "corpus_sha256": {corpus.name: sha256_tree(corpus) for corpus in corpora},
                    "labels": labels,
                    "results": results,
                    "threshold_failures": threshold_failures,
                },
                indent=2,
            )
        )
    else:
        print(render_markdown(results))
    return 1 if threshold_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
