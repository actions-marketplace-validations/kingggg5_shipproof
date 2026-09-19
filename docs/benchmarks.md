# Benchmarks and evaluation methodology

Every number on this page comes from a command you can run. If one does not reproduce, it is stale; please open an issue.

## Reproducing everything

```bash
# Fixture battery: file-level and line-level precision / recall / F1 against shared labels
python benchmarks/head_to_head.py fixtures/vulnerable-node-api \
  fixtures/vulnerable-python-api fixtures/node-taint-crossfile \
  fixtures/adversarial-node fixtures/secure-node-api \
  fixtures/node-secure-crossfile --repeat 3 \
  --min-file-precision 0.95 --min-file-recall 0.95 \
  --min-line-precision 0.95 --min-line-recall 0.95

# Throughput
python scripts/benchmark-scanner.py --files 1000 --samples 3 --jobs 4
python scripts/benchmark-scanner.py --files 250 --samples 3 --profile adversarial-regex --bytes-per-file 4096
python scripts/benchmark-scanner.py --files 8 --samples 3 --profile adversarial-regex --bytes-per-file 524288

# Open-source battery (network required; fetches reviewed immutable commits into benchmarks/.work)
python scripts/eval-realworld.py

# Clean-corpus precision (network; isolated installs; labels are optional)
python scripts/eval-clean-corpus.py --json --labels

# Offline precision-threshold gate against a report or the checked-in baseline
python scripts/check-precision-trend.py
python scripts/check-precision-trend.py --report path/to/benchmark-clean-corpus.json

# Advisory shadow lane for fixture-ready research prototypes (does not promote)
python scripts/eval-shadow-prototypes.py --json
```

CI runs the fixture battery and throughput check weekly ([.github/workflows/benchmarks.yml](../.github/workflows/benchmarks.yml)) with the real-world clone step and the Semgrep comparison behind opt-in flags.

## Fixture battery

Six small repositories serve as executable contracts: two intentionally vulnerable single-file APIs, one multi-file Node corpus whose taint crosses three files, one adversarial suite of precision traps, and two secure counterparts that must produce zero findings. Labels mark which files and sink lines contain issues. File-level scoring remains the compatibility contract; line-level scoring measures whether findings land on the labeled sinks.

Latest controlled-corpus run (Windows 11, Python 3.12.10, `--cross-file`, median of 3, 2026-08-26):

| Corpus | Findings | TP | FP | FN | TN | Context only | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| vulnerable-node-api | 2 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| vulnerable-python-api | 3 | 1 | 0 | 0 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| node-taint-crossfile | 6 | 4 | 0 | 0 | 1 | 1 | 1.0 | 1.0 | 1.0 |
| adversarial-node | 4 | 4 | 0 | 0 | 3 | 2 | 1.0 | 1.0 | 1.0 |
| secure-node-api | 0 | 0 | 0 | 0 | 1 | 0 | n/a | n/a | n/a |
| node-secure-crossfile | 0 | 0 | 0 | 0 | 6 | 0 | n/a | n/a | n/a |

Two caveats. The adversarial corpus contains vulnerable-looking code confined to comments and string literals; detectors must stay silent there while still catching disguised chains elsewhere—both directions are asserted in tests. The version-3 labels list expected sink lines plus source/helper chain files. Context-only files stay hashed but do not count as false negatives for a sink-reporting engine. Line-level precision and recall are gated in CI at 0.95 on the ShipProof self-leg.

Sink-line contract on the same corpora (ShipProof `--cross-file`, 2026-09-15). File-level still collapses two `SP108` hits in `routes/admin.js` into one path+rule count; line-level counts both sinks:

| Corpus | Line TP | Line FP | Line FN | Precision | Recall | F1 |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| vulnerable-node-api | 2 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| vulnerable-python-api | 3 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| node-taint-crossfile | 7 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| adversarial-node | 4 | 0 | 0 | 1.0 | 1.0 | 1.0 |
| secure-node-api | 0 | 0 | 0 | n/a | n/a | n/a |
| node-secure-crossfile | 0 | 0 | 0 | n/a | n/a | n/a |

## Open-source battery

`eval-realworld.py` now reads [a reviewed manifest](../benchmarks/realworld-repositories.json), fetches full immutable commits with isolated Git configuration, an empty hook template, non-interactive credentials, and a per-command timeout, verifies the declared license file, and records revision, license and corpus digests. A failed fetch, timeout, revision mismatch, or missing license is invalid evidence (exit `2`), never a skipped pass. The output deliberately marks every finding `unreviewed`; repository-level labels such as “clean baseline” or “intentionally vulnerable” do not prove that an individual alert is a true or false positive. Historical moving-HEAD counts were removed because they were not reproducible evidence.

The 2026-08-24 manifest run fetched and scanned all six pinned revisions successfully: 1,805 files, 732 total findings, and 310 application-scope findings. These are inventory counts only. In particular, findings in the three clean-baseline repositories still require human review, so this run supplies no real-world precision or false-positive claim.

## Clean-corpus precision

`scripts/eval-clean-corpus.py` installs the packages in [clean-corpus.json](../benchmarks/clean-corpus.json) into an isolated workspace (Python virtualenv, `npm install --ignore-scripts`, `go mod download`, `cargo fetch`), digests only scannable source, and scans with default ShipProof. Missing toolchains, install failures, or digest mismatches exit `2`. `--labels` scores [benchmarks/labels/](../benchmarks/labels/) JSONL against `schemas/finding-label.schema.json`; unlabeled findings stay `unreviewed` and are not counted as true or false. This corpus is a quiet-code baseline, not a proof that the packages are vulnerability-free. The pinned set is at least 30 packages across Python, JavaScript, Go, and Rust.

Checked-in engine-pass measurement (Windows 11, Python 3.12.10, 2026-09-15, ShipProof 0.10.0, `benchmarks/clean-corpus-baseline.json`): 15/15 packages scanned, 0 blocked, 63 application-scope findings, 0 high or critical, 10 medium gate findings, 53 advisory SP061, 1 high risk-confidence finding (urllib3 `SP310`), all 15 classified as library. High/critical FP-budget violations: none. Unreviewed high/critical rows: none. The ten medium leftovers are labeled `false_positive` in `benchmarks/labels/clean-corpus.jsonl` after reviewing upstream source (OpenAPI schema fields, HTTPS-redirect helper, queue drain, opt-in pickle, regex singleton caches). Compared with the 2026-09-15 pre-engine snapshot in [precision-plan.md](precision-plan.md) (11/15 blocked, 38 high findings, 71 high-confidence of 98), default `BLOCK` from this corpus is gone, verdict-affecting high+medium findings dropped from 45 to 10, and high risk-confidence dropped from 71 to 1. That is a measurement of this pinned corpus, not a published precision claim.

[precision-thresholds.json](../benchmarks/precision-thresholds.json) is the 3.3 gate: 0 blocked packages, 0 high/critical app findings, gate high+medium ≤ 22 (half of the original 45), high-confidence ratio ≤ 0.5, empty FP budget, 0 unreviewed high/critical. The weekly clean-corpus job and the release workflow run `scripts/check-precision-trend.py` against live artifacts or the checked-in baseline. Do not copy those ceilings into a README precision percentage without a labeled confusion matrix.

## Performance

Measured by [scripts/benchmark-scanner.py](../scripts/benchmark-scanner.py), which now records every sample, median, p95, fixture digest, workload bytes, warmup count, runtime identity, and peak RSS. A 2026-08-26 Windows/Python 3.12 local run measured:

- 1,000 clean 128-byte files: median 0.7675 s, p95 0.7744 s, peak RSS 28.68 MB (5-second reference budget passed).
- 250 adversarial-regex 4 KiB files: median 2.2336 s, p95 2.3359 s, peak RSS 26.53 MB (5-second stress budget passed).
- 8 adversarial-regex 512 KiB files: median 8.2779 s, p95 8.3140 s, peak RSS 28.32 MB (10-second large-file stress budget; the stricter 5-second exploratory target did not pass).

Throughput is re-checked after engine changes; the JS/TS analyzer and SARIF enrichment did not move it measurably.

## Scope and operating limits

ShipProof is one layer of an application-security stack. It scans source code deterministically, fully offline, with no repository or contributor limits. Capabilities that belong to other tool lanes are listed here so teams can pair dedicated products instead of expecting them from this gate:

| Capability | ShipProof today | Suggested pairing |
| :--- | :--- | :--- |
| Cross-file interprocedural taint | shipped (`--cross-file`, JS/TS + Python) | - |
| Secrets detection with redaction | shipped (50+ rules) | secret-history scanners for git history |
| Live credential validation | not claimed (requires network) | secret-validation platforms |
| SBOM / license compliance | not claimed | OSV-Scanner, Trivy |
| Dependency reachability analysis | not claimed | supply-chain scanners |
| Historical git scanning | shipped as bounded `scan --history` added-line evidence | Gitleaks for broader history validation and rotation workflows |

## Limitations

- Labels now include sink lines for the fixture battery. File-level scoring still treats any finding in a positive file as a true positive; line-level scoring requires the labeled path and line.
- Fixture corpora are authored in this repository. They prevent regressions and document intent, but they cannot substitute for third-party benchmark suites.
- The OSS battery is immutable by commit, but its findings still need manual per-alert review before precision claims.
- Semgrep comparison remains opt-in. The Linux workflow input `run-semgrep` installs Semgrep and runs the original ruleset in [benchmarks/semgrep-comparison/](../benchmarks/semgrep-comparison/). Until that job is run, we publish no comparative speed or accuracy numbers.
- Backlog triage uses keyword classification; individual targets get re-tiered on close inspection.

## OWASP Benchmark license review

Reviewed 2026-09-15 from the upstream LICENSE files, not from a vendored copy:

| Corpus | License | Decision |
| :--- | :--- | :--- |
| [BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava) | GNU GPL v2.0 | Do not vendor, copy, or ship inside ShipProof |
| [BenchmarkPython](https://github.com/OWASP-Benchmark/BenchmarkPython) | GNU GPL v3.0 | Do not vendor, copy, or ship inside ShipProof |
| [BenchmarkUtils](https://github.com/OWASP-Benchmark/BenchmarkUtils) | GNU GPL v3.0 | Do not vendor scoring utilities |

GPL copyleft is incompatible with placing those suites in this repository's default artifact. BenchmarkJava is also a Java web app, and ShipProof's default scanner has no Java engine that could score it honestly. An optional maintainer checkout outside the package remains possible later; it would stay an external evaluation, never a bundled corpus, and would not be a public precision claim until labels exist.

## Planned next measurements

1. Record the first Linux `run-semgrep` artifact against the original comparison ruleset and keep it as a trend input, not a superiority claim.
2. Weekly workflow artifacts published as release checks once the first scheduled run completes.
