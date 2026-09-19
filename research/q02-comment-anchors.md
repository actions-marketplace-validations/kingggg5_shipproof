# Q02 external anchor validation — implementation record (2026-09-15)

Status: implemented on top of Q01. All Q02 acceptance cases pass.

## What changed

- New `skills/audit-production-readiness/scripts/comment_anchors.py` (shipped, allowlisted):
  `comment-anchor/1.0` validation. Claimed line numbers are re-checked against file bytes,
  never trusted. `resolved` only on exact excerpt match (CRLF/LF-normalized) at the claimed
  spot or at exactly one in-scope location (relocation recorded, never silent).
  `unresolved` on zero matches (kept as review question), 2+ matches (ambiguous, including
  repeats inside one file), out-of-scope matches, stale revision, or incomplete search scope.
  Only `resolved` anchors are `inline_eligible`, so invalid anchors can never auto-publish
  as inline findings. Position-correct vs allegation-correct stay separate (`anchor_status`
  only; no verdict on the claim itself).
- Sides: `new` resolves against `--root`, `old` against `--old-root` (defaults to root), so
  old-side deletion anchors resolve against old bytes while new-side claims on deleted regions
  stay unresolved. Rename preserves side/revision via unique-match relocation; out-of-scope
  relocation stays unresolved.
- Scope: explicit `--scope` list or whole tree minus VCS internals (`.git`/`.hg`/`.svn`,
  same as the scanner). File cap bounds work, not correctness: over-cap scopes still verify
  direct claims but refuse uniqueness claims. Binary/undecodable bytes decode with
  `errors="replace"` so ASCII excerpts stay searchable instead of voiding the scope.
- New `schemas/comment-anchor.schema.json` (shipped, allowlisted).
- New `scripts/validate_comment_anchors.py` (maintainer workflow, not shipped): exit 0 with
  report, 1 with `--fail-on-unresolved` when any anchor is unresolved, 2 on malformed input.
- New `tests/test_comment_anchors.py` (15 tests): repeated code in-file and cross-file,
  Unicode path/content, CRLF/LF, old-side deletion pair, rename relocation + record,
  out-of-scope rename, stale revision, fabricated range, number revalidation (right excerpt
  at wrong lines relocates with `claimed_range_valid: false`), malformed shapes exit-by-error,
  unresolved-never-inline, VCS pruning, capped-scope uniqueness refusal.

## Verification

- 15 anchor tests + 31 combined (Q01/Q02/importer) pass; `ruff check .` clean;
  `git diff --check` clean; self-scan exit 0 (`PASS_WITH_EVIDENCE`, 411 files, 0 app).
- End-to-end CLI verified on the working tree (`package.json` anchor resolves).

## Known failures kept separate (not masked)

- Earlier size values were captured before the final package allowlist prune. The current package
  check passes at 125 files, 489,294 packed bytes, and 1,855,451 unpacked bytes under the
  existing 1,860,000-byte budget. Maintainer-only packet/anchor/trail workflow modules remain
  source-checkout tools and are not shipped in the runtime artifact.
