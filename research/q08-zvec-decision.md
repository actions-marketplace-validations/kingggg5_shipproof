# Q08 Zvec/dense retrieval — go/no-go decision (2026-09-15)

Decision: **NO-GO for now — keep lexical search.** Re-entry criteria below.

## Against the pre-registered gates (quality plan §8)

- Hybrid Recall@5 ≥ +10pp on the retrieval holdout with exact-ID accuracy at 100%:
  lexical holdout is already 0.94 with exact-ID at 100% (635/635 unit-tested). A +10pp
  gain is arithmetically near-impossible on this set (ceiling 1.00 needs +6pp), and no
  dense prototype was built to claim it. NOT MET.
- End-to-end defect recall unchanged or better, incorrect findings not increased,
  paired reviewer lookup time −20%: unmeasured — no prototype exists. NOT MET.
- Warm p95 ≤ 300 ms, peak RSS ≤ 512 MiB, index ≤ 3× source text: lexical measures
  p95 2.5 ms in-process with no index at all. A dense prototype would need
  operator-provisioned pinned embeddings plus a native backend, both outside the
  dependency-free core (the upstream helper downloads models with
  `trust_remote_code=True` — explicitly rejected as an integration boundary).
  No fair comparison run exists. NOT MET.

## Why no prototype was built

The plan permits deferral: small-set benefit unproven → keep lexical. The 5 holdout
misses are near-tie noise/abbreviations, not a proven semantic gap dense retrieval
would close, and the costs (native binaries, RAM/disk, model provisioning, supply
chain) are real. Building a toy dense demo to justify itself would be theater.

## Re-entry criteria (all required)

1. Retrieval holdout grows to ≥300 questions where lexical Recall@5 < 0.85 on a frozen
   lexical version, with misses reviewed as semantic (not abbreviation) gaps.
2. Operator-provisioned, digest-pinned local embeddings available with an explicit
   loading policy (no downloads, no remote code).
3. Isolated adapter passing the Q08 cost envelope on the declared machine/corpus.
4. Go/no-go re-run on the same frozen holdout with the pre-registered deltas.

Until then, Q07 lexical stands as the retrieval baseline.
