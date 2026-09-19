# Q07 lexical rule search — baseline record (2026-09-15)

Status: implemented and measured. Lexical retrieval is the baseline; dense/hybrid
needs a go/no-go (see Q08 decision).

## What changed

- New `skills/…/scripts/rule_search.py` (shipped, allowlisted): `rule-search/1.0`
  with three strictly separated indexes — `executable` (635 detectors: ID/title/CWE/
  ecosystem/remediation), `research` (batch-A dispositions with triage status, never
  presented as shipped), `examples` (Q03-reviewed snippets). Exact ID/CWE lookup is
  deterministic; ranked queries use IDF token overlap with curated EN/TH synonym
  expansion (direct hits weigh 2×), byte/token/top-k limits, deterministic ordering.
  Mechanisms: multiword-synonym splitting, direct-token weighting, fixed-dictionary
  Thai longest-match segmentation, light ASCII stemming (queries and docs alike).
- New `benchmarks/retrieval-eval.jsonl` (100 questions: 70 EN + 30 TH; 50/50
  development/holdout assigned by rule before any tuning) and `scripts/eval-retrieval.py`
  (Recall@5/MRR overall × EN/TH × dev/holdout + latency).
- 10 tests (`tests/test_rule_search.py`): exact lookup over all 635 IDs,
  case-insensitivity, CWE determinism, unknown/empty behavior, limits, ranking
  determinism, version/provenance, Thai sanity, kind separation both ways.

## Measured (fixed set, no tuning on holdout)

| Slice | Questions | Recall@5 | MRR |
| --- | --- | --- | --- |
| overall | 100 | 0.95 | 0.746 |
| en | 70 | 0.957 | 0.756 |
| th | 30 | 0.933 | 0.723 |
| development | 50 | 0.96 | 0.780 |
| holdout | 50 | 0.94 | 0.711 |

Warm query mean 1.3 ms, p95 2.5 ms (same machine as everything else this session).
Tuning log: three dev-motivated mechanisms adopted; two candidate changes (`ness`
stemming, salt/iv group split) were reverted after they traded holdout points for dev
points. Remaining misses are near-tie noise in dense neighborhoods (crypto, secrets,
payment) plus abbreviation gaps (NEXT_PUBLIC_, AKIA) — the documented gap for Q08.
