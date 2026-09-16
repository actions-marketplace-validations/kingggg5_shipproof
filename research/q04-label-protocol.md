# Q04 label protocol: two-reviewer finding labels

Status: protocol + harness implemented 2026-09-15. No confirmed labels exist yet;
everything below is required before any precision/recall claim.

## Vocabulary

`true_positive` / `false_positive` / `needs_context` / `duplicate` (existing
`finding_labels.py` terms). Automated or model output is `provisional` forever; only
agreed human review becomes `confirmed`.

## Reviewers

- Two independent reviewers label the same finding set (same corpus/package/revision/
  fingerprint). Records carry `reviewer` and `status`; the loader accepts two records
  per finding keyed by reviewer and rejects a reviewer labeling twice.
- `agreement_summary` reports Cohen's kappa over double-labeled findings plus the
  disagreement list. Bar: kappa ≥ 0.8 before `confirmed` labels support a release claim;
  every disagreement is adjudicated in notes and re-labeled by agreement.
- `index_labels` resolves a finding to one record for scoring (confirmed wins ties),
  but scoring output always separates `reviewed_confirmed` from `reviewed_provisional`.

## Split discipline

- Label and fix work uses development-split repos only. Before/after pairs, forks, and
  duplicate snippets stay in one split. If holdout results ever guide a detector change,
  that holdout is reclassified as development and a fresh holdout is designated.
- The evaluator runs development by default; `--include-holdout` marks output
  `holdout_used: true` as an audit trail.

## Ground truth for recall

- Recall needs `benchmarks/ground-truth/<repo>.json` (schema beside it): defects sourced
  from advisories, fix commits, or challenge catalogs — never from scanner alerts.
  A defect counts recalled when an app finding shares its path within ±5 lines.
- Without ground truth the report says `recall: unknown`. Labeling only scanner-reported
  items measures triage, not missed bugs, and must never be presented as recall.

## Denominators and uncertainty

- Every cohort report carries per-repo files/KLOC, finding counts by severity/proof,
  duplicate rate, reviewed/unreviewed split, and sample counts with the label status.
  "Clean repo" is never a label by itself: clean-baseline repos still need finding-level
  review of every blocking alert before a zero-FP statement, phrased as "zero observed".
- Fix success is tracked by before/after re-scan plus time-to-confirmed-fix, not by the
  alert disappearing alone.
