# Q05 review packets — implementation record (2026-09-15)

Status: implemented. No new public command (opt-in `--packet-out` flag only).

## What changed

- New `skills/…/scripts/review_packets.py` (shipped, allowlisted): `review-packet/1.0`
  builder. Each packet binds Q01 target/config identity (computed over the packet's
  selected files), selected findings, Q02 anchor questions for unanchored items,
  deterministic related files (same-directory siblings; impact-graph injectable via
  `related_fn`), source roles (app/test/example/rule-data/generated/unknown + basis,
  context only), redacted source text, and open questions. Bounds: ≤10 files and
  ≤128 KiB per packet, ≤20 packets; anything dropped is recorded and voids
  `complete`. Token counts labeled estimates. Lifecycle selected → scheduled →
  completed/failed/deferred; `reconcile()` folds agent responses with first-wins
  duplicates, wrong-packet/unknown-packet notes, timeout/error → failed, and missing
  responses never completing items.
- `scan_repo.py`: opt-in `--packet-out DIR` (existing directory, symlink-safe writes
  via `safe_write_text`, summary on stderr). Lazy import keeps the default path
  untouched; gate verdict and exit codes unchanged (verified identical with/without).
- `lib/cli.mjs`: `--packet-out` registered as a value option so root resolution skips it.

## Verification

- 10 tests (`tests/test_review_packets.py`): accounting, byte/file caps, redaction,
  roles, estimate labeling, reconcile (complete/dup/unknown/wrong-packet/timeout/
  missing), builder purity, CLI ledger + gate-parity, missing-dir exit 2.
- End-to-end via Python and Node CLIs; Node `cli.test.mjs` 19 pass; `ruff` clean;
  self-scan exit 0, 0 app findings. No provider adapters exist, so there is nothing
  that could send source out; any future one needs explicit opt-in per this contract.
