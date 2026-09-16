# Q06 verification + triage trail — implementation record (2026-09-15)

Status: implemented. Raw findings and external hypotheses stay separated by construction.

## What changed

- New `skills/…/scripts/triage_trail.py` (shipped, allowlisted): `triage-assessment/1.0`
  validation (trigger/evidence/counterevidence/uncertainty/remediation/test_method;
  untriggered proposals rejected upstream as needs-context), native-vs-external
  enforcement (imported keeps `original_rule_id`, never `SPxxx`, never L1/L2; only human
  review confirms), `Trail` append-only JSONL with hash chain (tamper-evident, counts
  reconcile: raw_findings/assessments/confirmed/quarantined), `RoundBudget` (monotonic
  reads/calls/time/output/tokens; retries never reset), deterministic duplicate
  suggestions (never auto-merge), and `verify_fix` requiring clean re-scan AND attested
  passing test together.
- Prompt-injection tripwires quarantine the assessment while findings stand (documented
  heuristic boundary, not a jailbreak-proof claim).
- New `schemas/triage-assessment.schema.json` (shipped, allowlisted).
- New `scripts/triage.py` (maintainer CLI, not shipped): append-finding,
  append-assessment, suggest-duplicates, verify-fix (exit 1 when unverified), counts.
- 9 tests (`tests/test_triage_trail.py`): vocabulary parity with finding_labels,
  three masquerade rejections, human-only confirmation, quarantine + chain tamper,
  budget monotonicity, suggestion-only duplicates, fix conjunction, count
  reconciliation.

## Verification

9 tests pass; `ruff` clean; self-scan exit 0, 0 app findings. Model assessments stay
`unconfirmed` by construction, matching the Q04 label protocol (provisional forever
without human agreement).
