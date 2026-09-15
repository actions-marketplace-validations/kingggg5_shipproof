# zvec-grep adoption review

Date: 2026-09-04. Status: review plus scoped P0/P1 precision and MCP-freshness fixes. No zvec-grep code, dependency, model, service, or semantic-search integration has been incorporated.

## Decision

**Adapt selected ideas; do not import zvec-grep into ShipProof's core.** The highest immediate return is using this pinned repository as a precision-regression corpus. The review reproduced several ShipProof false positives on real, unrelated TypeScript code and safe workflow configuration.

MCP evidence freshness is now protected by removing verdict reuse. Rule discovery without embeddings remains a possible next step. Keep an external semantic-search integration experimental and opt-in, and require measured benefit before adding it. Search relevance must never become vulnerability confidence, proof level, scan coverage, or a release verdict.

สรุป: คุ้มที่จะนำแนวคิดมาปรับใช้ แต่ไม่ควรยกทั้งระบบมา สิ่งที่ควรทำก่อนคือแก้ false positive ที่พบจริง ตามด้วยความสดใหม่ของ evidence และการค้นหากฎแบบ offline ไม่ใช่เพิ่มจำนวนกฎหรือ dependency ทันที

## Intake and scope

- Upstream: [zvec-ai/zvec-grep](https://github.com/zvec-ai/zvec-grep).
- Reviewed commit: [`891401e1f1e6862928d414834f8fac9ac00e0ff5`](https://github.com/zvec-ai/zvec-grep/tree/891401e1f1e6862928d414834f8fac9ac00e0ff5), package version `0.2.1`.
- Downloaded to `.shipproof-research-cache/zvec-grep`, an existing Git-ignored research area. Detached checkout; no submodules, repository hooks, or install scripts were run. The inspected tree had no Git symlink/submodule entries.
- Reviewed architecture, extraction, search/ranking, indexing/freshness, job scheduling, remote-embedding authorization, MCP transport, managed ripgrep, model download, manifests, package/lockfile, CI, and selected tests.
- The primary reviewer made security and adoption decisions. An isolated read-only helper mapped functions to tests; this was not an independent security audit.
- Existing ShipProof changes were preserved. This review adds no scanner rule, dependency, public command, service, or agent configuration.

## What the project actually does

zvec-grep is a local-first **retrieval** system: managed ripgrep for exact search, plus an index with lexical/BM25 and vector retrieval. Code symbols and source ranges become searchable fragments. Ranked results can combine several query routes using reciprocal rank fusion (RRF).

It is not a security scanner, a taint engine, a proof system, or a replacement for ShipProof's deterministic gate. Its search-oriented exclusions and bounded top-k results cannot establish that an entire repository has been inspected. See the upstream [pipeline](https://github.com/zvec-ai/zvec-grep/blob/891401e1f1e6862928d414834f8fac9ac00e0ff5/docs/04-pipeline.md) and [architecture](https://github.com/zvec-ai/zvec-grep/blob/891401e1f1e6862928d414834f8fac9ac00e0ff5/docs/05-architecture.md).

## Functions and systems worth adapting

Paths and line numbers below refer to the pinned upstream checkout, unless explicitly labeled ShipProof. Recommendations are new ShipProof designs, not claims that upstream already provides their stronger guarantees.

| Upstream implementation | Useful behavior | ShipProof decision |
| --- | --- | --- |
| `searchWorkspaceIndex`, `collectAdaptiveRecall`, `fuseCandidates`, `candidateToHit`; `src/engine/pipeline/search/index.ts:89`, `:520`, `:1147`, `:1174` | Separate retrieval routes, bounded recall depth, rank fusion, source attribution, and per-hit traces | Adapt a small lexical rule-catalog search first. Only add RRF if there are independently useful ranked sources. Do not map its score to severity/confidence. |
| `CodeExtractor.extractForIndexing`; `src/engine/extraction/code/extractor.ts:39`; `evidenceToSearchHitEvidence`; search pipeline `:1190` | Source ranges, symbol metadata, and explicit fallback to text chunks | Reuse the source-envelope concept for reviewed rule/explanation lookup. Extend existing evidence fields, not a second incompatible finding format. Re-read cited source before claiming current evidence. |
| `computeDiffFromFiles`; indexing pipeline `:647`; `RootRuntime.markDirty`/`markIndexed`/`markReconciled`; `src/daemon/root-runtime.ts:193`, `:198`, `:229` | Track changed content and distinguish indexed generations from pending changes | Adapt generation/freshness metadata; do not copy the same-size/same-mtime shortcut into a release gate. |
| `IndexCoordinator.enqueue`; `src/daemon/index-coordinator.ts:30`; `JobScheduler.submit`; `src/daemon/job-scheduler.ts:77` | Coalesce work per canonical root and preserve changes arriving during a running job | Useful only if repeated IDE/MCP scans justify it. Use bounded single-flight work keyed by complete scope and policy, with cancellation ownership. No daemon needed for one-shot CLI scans. |
| `createRemoteEmbeddingTarget`, authorization planner/guard/store; `src/authorization/target.ts:38`, `planner.ts:8`, `operation.ts:36`, `store.ts:48` | Separate endpoint authentication from permission to send repository content; bind grants to roots/provider/model/endpoint and support revocation | Adapt this separation only for a future opt-in external adapter. A config flag, retrieved document, or tool annotation must not grant new authority. Default ShipProof stays offline. |
| `remoteEmbeddingRequestState`, `matchesRemoteEmbeddingRequestState`; `src/mcp/request-state.ts:202`, `:217` | Bind a continued approval flow to tool arguments, target, disclosure, expiry, and replay protection | Useful if ShipProof later has resumable approvals. No need to add the machinery to today's read-only stdio workflow. |
| `assertRootScopedPaths` / `assertRootScopedPath`; `src/cli/managed-rg.ts:344`, `:367`; bounded schemas in `src/mcp/schemas.ts:4` | Reject shell operators, validate canonical paths and auxiliary pattern/ignore files, cap query/filter sizes | Keep ShipProof's existing allowlisted argv, canonical roots, timeouts, and output caps. Add missing negative tests rather than another shell-command parser. |
| Search tool registration; `src/mcp/tools.ts:420` | Default agent surface is small; search reports freshness and compact snippets; annotations acknowledge possible writes/network | Adapt compact presentation where it reduces noise. Preserve ShipProof's structured evidence contract and redaction; do not imitate text-only output at the expense of machine consumers. |
| [Paired benchmark protocol](https://github.com/zvec-ai/zvec-grep/blob/891401e1f1e6862928d414834f8fac9ac00e0ff5/benchmarks/README.md) | Fixed tasks/environment, baseline versus treatment, index-preparation cost recorded separately, leakage controls | Extend ShipProof's existing real-world evaluator. Measure precision, recall, source correctness, incomplete coverage, wall time, and memory separately from agent tokens. Do not inherit upstream benchmark scores. |

### Avoid duplicating existing ShipProof features

ShipProof already has L0/L1/L2 evidence, rule explanations, context levels, trace output, suppression reasons, a completeness ledger, bounded subprocesses, and real-world corpus infrastructure. These are not new benefits supplied by a vector index. See `README.md:94`, `:153`, `:159`, `:318` and `lib/mcp-server.mjs:129`.

The concrete gap in rule discovery is that `shipproof explain` requires a rule ID (`lib/cli.mjs:680`). A small offline search over stable IDs, titles, CWE, ecosystems, and remediation can help without scanning user code into another database. Executable rules and research-only candidates must remain visibly separate.

## Reproduced ShipProof precision defects

The trusted local ShipProof scanner was run against the downloaded source, first normally and then with `--cross-file`. Both scans returned exit `1` and the same **56 heuristic alerts across 214 admitted files**: 46 application-scope and 10 test-scope; 52 high and 4 medium. Cross-file analysis added no flows. These numbers are **not 56 confirmed vulnerabilities**.

The scanner's supported-source completeness ledger was `is_complete: true`, with 12 assets and 2 binary files recorded. This does not mean native dependencies, binaries, all repository formats, runtime behavior, or benchmark execution were audited.

Six application-scope alerts were manually confirmed to be false positives across five rule IDs:

| Rule | Upstream evidence | Why the reported condition is absent | Required ShipProof regression boundary |
| --- | --- | --- | --- |
| `SP210` | `.github/workflows/ci.yml:48`–`:54` | PR title enters an environment variable and is read as data through `process.env`; it is not interpolated into the generated script | Distinguish YAML `env`/`with` data from interpolation in `run`. Keep unsafe inline-expression positives. |
| `SP220` | `.gitignore:31`–`:34` | An ignore entry for `.env` is reported as an environment file tracked in Git. `git ls-files -- .env '.env.*'` returned no paths in this checkout | Use actual tracked-path evidence; ignore-file text is not a tracked secret. Preserve positive fixtures with genuine tracked sensitive files and label unavailable Git evidence honestly. |
| `SP583` | `src/engine/models/backends/model2vec-worker-pool.ts:2`, `:119`–`:120` | `Worker` is imported from `node:worker_threads`, not BullMQ | Resolve API/import identity, including aliases and type-only imports. Separately validate whether any BullMQ setting is required for the claimed failure. |
| `SP597` | `src/daemon/server-controller.ts:143`–`:173` | The file is a Node daemon controller, not a Next.js Server Component; file-wide fetch counts do not establish a sequential SSR waterfall | Require framework/component evidence and same-execution-path dependencies. Separate functions, necessary sequential requests, comments, and unrelated Node files must stay silent. |
| `SP599` (two alerts) | `src/cli/args.ts:818`–`:820`; `src/daemon/change-set.ts:126`–`:168` | The first assertion is dominated by a nonempty-array check. The second is in a private path helper reached after a root guard. Neither location is a dynamic API response payload | Require the claimed source and missing guard, rather than treating every non-null assertion as a high-severity bug. |

The GitHub workflow finding is especially useful: upstream follows the environment-variable mitigation documented by [GitHub's secure-use reference](https://docs.github.com/en/actions/reference/security/secure-use#use-an-intermediate-environment-variable). ShipProof currently recommends the very pattern that it flags here. The cause is visible in ShipProof's expression-only rule at `scan_repo.py:7181`; `SP220` similarly matches text instead of Git tracking evidence at `:7316`.

Remaining alert groups must not be presented as an exploit count:

- **39 `SP203` alerts:** action references use version tags rather than full commit SHAs. This is a real immutable-pinning hardening gap, not evidence that 39 actions are compromised. Full-SHA pinning is recommended by [GitHub](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions).
- **One application `SP306` alert:** parallel runtime shutdown at `src/daemon/runtime-manager.ts:194`. Cardinality/resource exhaustion needs workload evidence; `Promise.all` alone does not establish a production failure.
- **Ten test-scope alerts:** include fixture credentials, explicit diagnostic-output tests, a custom Node worker pool misidentified as a connection pool, and cleanup over small test arrays. They are not application vulnerabilities. No live credential validation was attempted; credential-like strings were not copied into this report.

This is a deliberately selected repository, not a labeled representative benchmark. Do not calculate a general precision/F1 score from this run. The six application false positives are enough to justify focused regression work, not broad claims about every rule.

## Do not copy these upstream assumptions into a security gate

These are source-confirmed design constraints and adoption risks, not claims of verified remote exploits. No P0 exploit was established by this static review.

### 1. Freshness uses an optimization, not a content-attestation guarantee

`computeDiffFromFiles` accepts an existing entry as unchanged when size and mtime match and a previous content hash exists (`src/engine/pipeline/indexing/index.ts:672`–`:679`). It does not compute the current hash on that branch. A same-length edit with a preserved timestamp can therefore escape this diff check. Hashing and extraction also read the path separately (`:1103`, `:1658`), so this is not an atomic source snapshot.

For retrieval this can be an explicit performance tradeoff. For release decisions, use current bounded source reads, content hashes, scope/policy/ruleset identity, and explicit invalidation; an unverified or stale snapshot cannot silently become a fresh PASS. Proposed tests: equal-size/equal-mtime edits, deleted files, policy changes, stale generations, read failures, and changes between hash and extraction. Runtime reproduction of upstream behavior was not performed.

ShipProof has a related **opt-in** issue to address: `lib/mcp-server.mjs:56`–`:66` caches by arguments plus TTL, not source content. The default cache is off, but a configured TTL can serve a previous verdict after files change. Keep it off by default; before expanding caching, either remove verdict caching or bind it to verified inputs and expose freshness.

### 2. A local search service is not a per-project authorization boundary

Upstream authentication is intentionally optional: `resolveServerToken` returns no token without configuration, and `validRequestToken` then accepts requests (`src/daemon/config.ts:86`–`:107`; `src/daemon/http-server.ts:311`). Loopback binding, Host/Origin checks, request-size limits, and token comparison are useful controls. They do not distinguish authorized projects or local clients.

The server also constructs `/mcp/admin` with the full toolset using the same transport token (`http-server.ts:68`–`:80`, `:193`–`:212`). A search-only tools listing is therefore a UX choice, not a separate administrative permission. Before adapting this to a shared or untrusted-agent service, require authentication, explicit root allowlists, separate administrative authorization, and negative access tests. ShipProof's current stdio adapter does not need a new HTTP listener.

### 3. Some resource bounds stop before the expensive boundary

- `JobScheduler.createJob` retains every job, including its callback, in `jobs`; `finish` clears active-root state but does not prune completed history (`src/daemon/job-scheduler.ts:57`, `:276`–`:305`, `:314`–`:333`). Repeated completed jobs grow retained state over daemon lifetime. Add bounded history/TTL and release callbacks before borrowing this design; verify with a many-job soak test.
- Managed ripgrep's `runCommand` accumulates items, stdout buffer, and stderr. A result-count limit is optional and the function has no wall-clock timeout, byte ceiling, or abort input (`src/engine/service/lexical.ts:341`–`:439`). Exhaustive search is intentional, but an agent-facing gate needs streaming/bounded output with an explicit incomplete result instead of unbounded retention. Test huge output, a huge single line, slow child processes, stderr floods, and cancellation.
- File discovery has type-aware limits, but `readSource` and `withContentHash` subsequently use whole-file reads. Text can be admitted up to 256 MiB (`src/engine/file-size-policy.ts:4`). A prior stat is not a hard bound on a later read if a file grows or changes. Keep ShipProof's bounded-read approach and revalidate file identity/type at the read boundary.

These are static observations; no memory/latency or exploit benchmark of upstream was run. In particular, bounded worker concurrency must not be confused with bounded queued work, retained job history, or total memory.

### 4. Local inference still has supply-chain and setup costs

The [package manifest](https://github.com/zvec-ai/zvec-grep/blob/891401e1f1e6862928d414834f8fac9ac00e0ff5/package.json) requires Node `>=22`, has 12 direct runtime dependencies, and one optional `node-llama-cpp` dependency. ShipProof supports Node 20 and a dependency-free core.

Parsing the [npm lock's `packages` object](https://github.com/zvec-ai/zvec-grep/blob/891401e1f1e6862928d414834f8fac9ac00e0ff5/package-lock.json) gives 438 entries after excluding the root empty-string key, including dev, optional, and platform-specific entries; this is not the installed production package count. Five entries declare install scripts: `@zvec/zvec`, `node-llama-cpp`, `onnxruntime-node`, `protobufjs`, and `sharp` (`hasInstallScript` at lines 2133, 4371, 4520, 4818, and 5116). All inspected non-root entries have integrity fields, which is useful but does not audit installation behavior or prove absence of CVEs.

Local Model2Vec artifacts use pinned Hugging Face revisions, temporary downloads, and rename (`src/engine/models/catalog.ts`; `backends/model2vec.ts:291`–`:316`). Its download path follows redirects, has no explicit download deadline/byte cap, and accepts a cached file based on nonzero size (`:67`–`:94`, `:352`). Do not copy this as ShipProof's offline default or as a cryptographically verified artifact cache. A future adapter needs explicit provisioning, artifact hashes, bounded downloads, corruption recovery, and zero-egress tests after provisioning.

The upstream manifest can contain a plaintext embedding API key when embedding runtime settings are persisted, and its writer uses restrictive file modes (`src/engine/manifest.ts:11`–`:17`, `:40`–`:47`, `:127`–`:141`; runtime-key selection at `src/engine/service/zvec-grep.ts:1555`). Do not include credentials in ShipProof evidence or repository caches. Do not claim that POSIX mode values establish equivalent Windows ACL guarantees.

### 5. Structural extraction is not language-wide semantic analysis

`src/engine/code-formats.ts` and `extraction/code/tree-sitter/grammar.ts` provide structural grammars for C/C++, Go, Java, JavaScript/JSX, TypeScript/TSX, Python, and Rust. Vue/Svelte script blocks are handled separately. C#, PHP, and SQL use text fallback in this version; React/Angular framework behavior is not proved by parsing TS/JS symbols.

This is useful retrieval coverage, but it does not supply C#/PHP/SQL taint analysis, authorization reasoning, or additional executable ShipProof rules. Avoid importing the WASM/parser bundle merely to enlarge a language-support table.

## Recommended delivery order

Priorities here describe **ShipProof work**, not CVSS or upstream vulnerability severity. All items remain proposed, not completed.

| Priority | Bounded change | Acceptance evidence |
| --- | --- | --- |
| P0 release trust | Correct `SP210` and `SP220` false blocking; remove documentation wording that equates `--min-confidence high` with confirmed issues | Positive/negative/adversarial fixtures, YAML env-versus-run cases, actual Git tracking cases, no global suppressions; high confidence still explicitly distinct from proof/verification |
| P1 detector precision | Correct `SP583`, `SP597`, `SP599`; examine custom-pool and test-diagnostic look-alikes | Import/alias/type-only cases, framework and same-function checks, control-flow guards, unrelated-framework negatives; preserve genuine positives and exit codes |
| P1 evidence correctness | Review/remove opt-in TTL verdict caching before adding an index; define snapshot/freshness metadata if caching remains | A file or policy mutation cannot return a previous fresh PASS; cancellation, deletion, same-mtime edits, and ruleset changes covered |
| P1 evaluation | Add original minimal fixtures derived from this review and a pinned optional corpus entry | Record upstream commit/license and per-alert reviewer labels. Keep holdout repositories. Do not label the whole upstream repository secure or fetch it in default CI/scan |
| P2 usability | Offline rule lookup over existing metadata, ideally in `labs` before a new stable public surface | Exact rule IDs win; stable deterministic ordering; bounded query/results; unknown/no-match behavior; executable versus research status; Thai/English labels tested without relying on English-only word splitting |
| P2 experiment | Optional external semantic retrieval for maintainers/agents, only if lexical lookup is insufficient | Compare with existing lookup under equal budgets, report cold/warm and index-build cost, source correctness, retrieval misses, memory, and no-network behavior; delete the experiment if benefit is not material |

Suggested optional-adapter boundary:

```text
Explicit user request -> optional retrieval -> untrusted candidate locations
                                                |
                              re-read bounded current source + check scope/hash
                                                |
                              deterministic ShipProof analysis -> policy gate
```

The retrieval branch never filters the set of files the default gate must scan, promotes a research candidate into a rule, executes retrieved instructions, or changes an exit code. A suggested line range is a lead, not a trusted command or proof.

## Implementation follow-up: scoped P0/P1 fixes

The original scan below remains the pre-fix baseline. The follow-up uses independently written detectors and fixtures, not upstream source copied into ShipProof.

| Boundary | Implemented behavior | Regression evidence |
| --- | --- | --- |
| `SP210` | Interpret ordinary workflow step `run` scalars; do not treat `env`, `with`, names, YAML comments or embedded YAML prose as shell interpolation | 11 curated cases, including quoted/folded scalars and misleading `run` text in `env` |
| `SP220` | Require selected, successfully inspected environment paths to appear in a bounded, read-only Git-index listing. Do not infer tracking from file contents | 10 curated artifact cases; real Git tests cover tracked/untracked files, ignore text, nested roots, exclusions, unavailable Git and caller environment redirection |
| `SP583` | Require a visible BullMQ Worker binding and a literal `skipStalledCheck: true` option. Default options are not a defect | 14 curated cases; defaults, Node workers, type-only imports, aliases, shadowing and unknown option spreads |
| `SP597` | Require adjacent distinct literal default-GET requests in one exported async page/layout component, with Next.js applicability | 12 curated cases; independent/dependent requests, separate functions, client components, memoized duplicates, POST options and shadowed fetch |
| `SP599` | Require a local `json()` result followed immediately by a same-block non-null field dereference | 13 curated cases; assertion-only expressions, local fields, guards, validation, aliases, comments/strings and unrelated scopes |
| MCP freshness | Remove the optional TTL verdict cache. Legacy values are still validated, but nonzero values warn on stderr and are ignored | Real stdio MCP test: safe source -> risky source -> safe source -> deletion, with fixed mtime and identical byte lengths for edits |
| Evidence wording | Display `HIGH_CONFIDENCE`, not `CONFIRMED`; clarify that static confidence is not proof or verification | English/Thai README and rule explanations updated; JSON confidence and verification fields remain unchanged |

The precision fixture set contains **60 original cases** (16 positive, 34 negative, 10 adversarial), with at least 3 positive / 5 negative / 2 adversarial cases for each changed rule. Both the contract builder and tests execute the real detector on per-case inputs; framework eligibility is not simulated by the fixture generator. Artifact cases are supplemented by real Git integration tests. The full self-review also checks regex text versus executable code, token budgets, and avoiding repeated binding analysis across 600 imports.

Final follow-up verification, local Windows / Node `24.15.0` / Python `3.12.10`:

- `npm run check` returned `0`: lint passed; 77 Node tests passed; 673 Python tests completed with 1 skipped, plus 2 demo tests passed; the 115-file package manifest and isolated packed-artifact smoke test passed. This is local evidence, not a new hosted CI-matrix result.
- Both legacy contract builders report current deterministic output, their 12 contract tests pass, and `rule_assurance_report.py --format json --check` returns `0`.
- The final ShipProof self-scan returned `0` at the high gate: **302 files, 0 findings**. Coverage remains `CONDITIONAL` because 5 existing oversized files were not inspected; no size ceiling or exclusion was relaxed. Artifact: `.shipproof-research-cache/shipproof-precision-self-scan.json`.
- Re-scanning the pinned upstream returned **50 findings instead of 56**, removing exactly the 6 manually verified false positives and adding no new fingerprints. The 50 remaining alerts (40 application / 10 test; 47 high / 3 medium) are not 50 confirmed vulnerabilities. All 39 action-pinning hardening alerts remain. Normal and cross-file runs have identical finding fingerprints and both correctly return exit `1` at the high gate. Artifacts: `.shipproof-research-cache/zvec-grep-after-precision.json` and `.shipproof-research-cache/zvec-grep-after-precision-cross-file.json`.
- `git diff --check` returned `0`; the downloaded upstream checkout remains clean. The final scanner SHA-256 is `6cc7995a514ba671d7b9f98cb136375cc0059fa1811b2f289f2431b84aba9d9f`, still in the dirty ShipProof `0.10.0` worktree based on `56f8302923225e1aa037b2d9458fc0caf7e02e9f`.

Primary documentation consulted through Context7:

- BullMQ's default stalled checker and explicit opt-out: [WorkerOptions](https://github.com/taskforcesh/bullmq/blob/master/src/interfaces/worker-options.ts), [stalled jobs](https://github.com/taskforcesh/bullmq/blob/master/docs/gitbook/guide/jobs/stalled.md). The default `stalledInterval` is 30 seconds and `maxStalledCount` is 1. Missing those options is not evidence that recovery is disabled; another worker may deliberately own recovery.
- Next.js fetching and memoization: [fetching data](https://github.com/vercel/next.js/blob/canary/docs/01-app/01-getting-started/06-fetching-data.mdx), [fetch reference](https://github.com/vercel/next.js/blob/canary/docs/01-app/03-api-reference/04-functions/fetch.mdx). Cache hits and static prerendering affect whether sequential work delays real requests.
- Git-index evidence: [ls-files](https://github.com/git/htmldocs/blob/gh-pages/git-ls-files.html), [rm](https://github.com/git/htmldocs/blob/gh-pages/git-rm.adoc). NUL-separated paths retain filename boundaries and are relative to the scan directory; `git rm --cached` changes the index, not past history.
- Workflow interpolation guidance from the original review: [GitHub intermediate environment variables](https://docs.github.com/en/actions/reference/security/secure-use#use-an-intermediate-environment-variable).

Residual boundaries: these are deliberately narrow local checks, not full YAML/JavaScript/TypeScript parsers or a proof of runtime behavior. YAML flow maps/aliases and multiline expressions are unresolved. JS template interpolation, ambiguous lexical syntax, files above 50,000 context tokens, and BullMQ constructor spans above 512 tokens are not affirmative evidence for these scoped checks. Indirect bindings, custom validated `json()` methods, intentional request ordering, external queue recovery, and actual credential exposure still require review. Other existing scanner engines remain active; file-coverage completeness does not mean every language construct has been analyzed by every rule.

No exclusions, severity gates, or global suppressions were weakened. No upstream packages, models, daemons, or scripts were run. The security/design decisions and final QA were primary-agent self-review; a separate helper performed mechanical documentation/fixture integration, not an independent security audit. Existing user changes remain intact. No commit, push, version bump, or release was performed in this follow-up.

Remaining work from the broader proposal: label holdout corpora, review the unrelated custom-pool/test-diagnostic categories before changing those detectors, and measure whether offline metadata lookup is useful. Semantic retrieval remains an optional experiment, not a prerequisite for these fixes.

## Verification record (pre-fix review baseline)

Performed in this review:

1. Safe source download, pinned commit/version check, tree inspection, and clean target checkout check.
2. Static inspection of source, license, npm lock, CI definitions, and selected positive/negative tests. Upstream tests were read, not executed.
3. Direct ShipProof scan and cross-file scan, with identical finding fingerprints. No live endpoint, daemon, model, package installation, or target script was executed.
4. Manual validation of the six application-scope false positives and the action-pinning hardening category. No general precision/recall or CVE-clearance claim.
5. ShipProof's own `npm run check` returned `0`: lint/test/package checks and packed-artifact smoke passed. The package manifest verified 115 shipped files; the research clone/report are not new runtime dependencies. These are ShipProof checks, not upstream zvec-grep test results.
6. ShipProof self-scan returned `0` at the high gate: 297 files, zero application/test findings. Verdict remains `CONDITIONAL` because five existing research JSON files exceed the default source-size limit. No exclusions or size ceilings were relaxed. The report is `.shipproof-research-cache/shipproof-zvec-review-self-scan.json`.
7. `git diff --check` reported no whitespace errors in existing tracked changes; the new report was also checked separately. The downloaded target checkout remains clean.

Reproduction commands, from the ShipProof root, using only its trusted scanner:

```powershell
python skills/audit-production-readiness/scripts/scan_repo.py .shipproof-research-cache/zvec-grep --format json --fail-on high --output .shipproof-research-cache/zvec-grep-scan.json
python skills/audit-production-readiness/scripts/scan_repo.py .shipproof-research-cache/zvec-grep --cross-file --format json --fail-on high --output .shipproof-research-cache/zvec-grep-cross-file-scan.json
```

Both commands returned `1`, as expected from the raw high-severity alerts. Local JSON artifacts remain in the ignored research cache. The scans used the dirty ShipProof `0.10.0` worktree based on commit `56f8302923225e1aa037b2d9458fc0caf7e02e9f`; scanner SHA-256 was `e19e8a1c6a926e348095260d7a18ac9e99f329744b1bd787bbf1a5ceca63a824`. This pins the actual reviewed detector state rather than pretending HEAD alone reproduces it.

Upstream contains manifest, service/search, authorization, request-state replay, cancellation, CLI/package, and multi-platform CI tests. Examples include `test/authorization.test.mjs:23`, `test/mcp-request-state.test.mjs:52`, `test/integration/service.test.mjs:176`, `test/path-indexing.test.mjs:240`, and `test/job-scheduler.test.mjs:174`. Test presence and configured coverage thresholds are not a passing test result.

Not established: upstream installation safety, native dependency behavior, current dependency advisories, actual coverage percentage, runtime resource ceilings, Windows ACL parity, network/redirect behavior under attack, benchmark replication, or semantic-search benefit for ShipProof. Security, data/privacy, scale, operability, and supply-chain adoption gates therefore remain conditional; this review does not certify upstream production readiness.

## License and copying policy

The reviewed repository declares [Apache-2.0](https://github.com/zvec-ai/zvec-grep/blob/891401e1f1e6862928d414834f8fac9ac00e0ff5/LICENSE). Literal reuse requires preserving the license and relevant notices, marking modifications, and handling any applicable third-party notices; it must not be presented as ShipProof-authored MIT-only code. Apache-2.0 also does not grant general trademark rights. See the [Apache license](https://www.apache.org/licenses/LICENSE-2.0).

No standalone NOTICE file was found in the inspected tracked tree. This is not a transitive dependency or benchmark-dataset license audit. Do not copy bundled datasets or dependencies under an assumption that the root license covers every asset.

Recommended approach: independently implement the small applicable designs and original fixtures, retain provenance links, and copy no detector code, prompt bundles, model weights, or marketing claims. No upstream code has been incorporated into ShipProof by this review.
