# Q00 baseline snapshot — 2026-09-15

Pinned before Q01 implementation. Release bump work is recorded separately and not included implicitly.

- HEAD: `61e3f50f6bd0bf8b4c59d0f61bd97d64d2faa639`
- Plan baseline was `c692cc4548907f3f57aa7e2489edd1278e37f7da` (v0.11.0); tree has moved forward by:
  - `17f5dd6 fix: follow host PATH symlinks and keep research catalogs off the completeness gate`
  - `61e3f50 fix: treat leftover SARIF reports as assets, not unknown binaries`
- Tracked dirty-diff sha256: `ba7840ac6ec805e0f37dd56b8ce88b80702696761491c794176b18e66013846a`
  - 34 tracked files modified = pending v0.11.2 version bump (0.11.1 → 0.11.2 strings + `docs/releases/v0.11.2.md` + `packaging/approved-files.json` + `tests/test_structure.py` update)
  - Untracked: `docs/releases/v0.11.2.md`, `research/alibaba-adoption-review.md`, `research/shipproof-quality-plan.md`
  - `_bump_0_11_2.py` helper seen during `npm run check` lint failure, already removed from tree; `ruff check .` now passes
- Runtime/OS: Node v24.15.0, Python 3.12.10, Windows-11-10.0.26200-SP0
- Manifest: package.json version currently 0.11.2 in working tree (release bump), scanner reports `ShipProof 0.11.1` tool identity at pinned HEAD logic; treat as release-in-progress, not a new gate
- Effective options (self-scan): `python skills/audit-production-readiness/scripts/scan_repo.py . --fail-on high --format json`
  - exit 0, verdict `PASS_WITH_EVIDENCE`, files_scanned 402, app_findings 0, test_findings 29
  - completeness is_complete true, reasons [], assets 10 (intentional boundary), excluded 5, symlinks 0
- Rule assurance: `python scripts/rule_assurance_report.py --format json --check` passes
  - executable 635, complete 635, realistic_negatives 58, near_miss_only 577, high_critical_without_realistic 443
  - matches quality-plan baseline numbers
- Required checks:
  - `git diff --check`: pass
  - `tests/test_p0_p1_recheck.py + tests/test_coverage_suppression.py`: 57 passed, 3 skipped
  - `ruff check .`: pass (after helper removal)
  - `npm run check` full: re-run after Q01 changes; lint:node pending re-verification in Q10
- Trust/scope paired cases already covered by `tests/test_p0_p1_recheck.py`:
  - safe catalog data vs executable payload in same tree, nested scan root, selected/changed paths
  - runtime PATH shadowing (`_trusted_git_binary` lexical + canonical checks), output symlink/reparse (`safe_write_text`), parser failures, truncated Python, finding/line limits, terminal controls
- Q00 acceptance: safe + unsafe variants present in suite; intentional scope omission appears in ledger (assets/excluded); no unresolved regression making false evidence pass the gate. Proceed to Q01.
