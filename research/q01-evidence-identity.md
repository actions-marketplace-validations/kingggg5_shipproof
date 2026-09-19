# Q01 evidence identity — implementation record (2026-09-15)

Status: implemented on top of Q00 baseline (`61e3f50`, dirty bump tree). Q01 acceptance cases pass.

## What changed

- New `skills/audit-production-readiness/scripts/snapshot_identity.py` (shipped, added to
  `packaging/approved-files.json`): versioned `snapshot-identity/1.0` contract over relative
  posix paths, file bytes digests, selection digest, dependency context, scanner/rules identity,
  and secret-free effective-policy digest. Git mode pins resolved commit; workspace mode hashes
  bytes actually read through TOCTOU-guarded reads. No absolute install paths in identity.
  Windows case/8.3-alias tolerant containment (`_is_within_root`).
- New `schemas/snapshot-identity.schema.json` (shipped, allowlisted).
- New `scripts/compute_snapshot_identity.py` (maintainer workflow, not shipped — same status as
  `scripts/import_external_evidence.py`): prints `target_digest`/`config_digest` for trusted CI
  to feed back as `--expect-target` / `--expect-config`.
- `scripts/import_external_evidence.py`: strict validation (unknown/duplicate fields, null and
  coerced values, repository-relative paths, line ranges, future timestamps, byte/count/depth
  limits, O_NOFOLLOW + fstat guarded reads) plus `--expect-target`, `--expect-config`,
  `--max-age-hours`, `--clock-skew-minutes`, `--allow-unverified`, `--now` (tests). Returns
  `identity_matches`, `authorship_verified: false`, `review_complete: false`,
  `assessment_verified: false`, `gate_eligible` / `resume_eligible` (true only when verified),
  and a `verification` block stating digest equality is identity, not authorship. Old
  envelopes remain readable as `unverified` (gate-ineligible); mismatched/stale evidence with
  an explicit policy exits 2. Old age alone never rejects when no expiry policy is set.
- `lib/evidence.mjs`: same contract in `loadImportedEvidence(path, options)` with duplicate-key
  detection, depth checks, guarded reads, and identical verification fields; `gate evidence
  --import` accepts `--expect-target`, `--expect-config`, `--max-age-hours`,
  `--clock-skew-minutes`, `--allow-unverified`. Default scan path untouched (still offline,
  read-only, dependency-free; exit 0/1/2 unchanged).
- New `tests/test_evidence_identity.py` (14 tests): stable identity, same-size/same-mtime edit,
  deletion, rename/move, policy/rule change, secret separation, absolute-path independence,
  verified match, wrong-root mismatch (fail-closed + `--allow-unverified` readability), old
  evidence without expiry, max-age staleness, future timestamps, malformed suite, end-to-end
  repo-A vs repo-B mismatch.

## Verification

- `tests/test_evidence_identity.py` + `tests/test_import_external_evidence.py`: 16 passed.
- `tests/test_structure.py`: passed. `rule_assurance --check`: 635/58/577/443 unchanged, gate passed.
- Node `platform`, `command-contracts`, `hardening` suites: pass. CLI: default import exit 0
  (`unverified`), mismatch exit 2, match exit 0 (`verified`).
- `ruff check .`: pass. `git diff --check`: pass.
- Self-scan `--fail-on high`: exit 0, `PASS_WITH_EVIDENCE`, 407 files, 0 app / 29 test findings,
  complete. (Two transient SP061-low findings from a broad `except` in the new compute script
  were triaged and fixed by narrowing to `ImportError`; no exclusions or budget changes.)

## Known failures kept separate (not masked)

- Earlier package-size measurements in this record were pre-prune diagnostics. The final
  allowlist excludes maintainer-only workflow modules and the large development plan; current
  `npm run pack:check` passes at 125 files, 489,294 packed bytes, and 1,855,451 unpacked bytes
  under the existing 1,860,000-byte budget. No budget was raised to make this pass.
- Scan-report builders were intentionally left schema-unchanged (no breaking change, no
  migration smuggled in); snapshot binding travels via the compute script + Q05 packets.

## Next

Q02 external anchor validation (`revision/path/side/range/excerpt`, single-match-or-unresolved,
rename/deletion side handling) builds on the `check_evidence_path` foundation here.
