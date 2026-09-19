# Q03 realistic assurance — cohort 1 (2026-09-15)

Status: COMPLETE. 21 rules reviewed, 20 debt items closed.
Debt 443 → 439 → 434 → 429 → 424 → **423** (acceptance: ≤423 ✓).
(SP101 was already realistic before this work; it still gained a reviewed counterpart.)

## Selection (gate impact + reproduced noise + prevalence)

- SP103 SQL interpolation (high): 5 self-scan hits — reproduced noise.
- SP101 eval/exec (high): 1 self-scan hit — reproduced noise.
- SP138 signature `==` (high), SP151 subprocess shell=True (high), SP163 unverified
  SSL context (high): no current corpus hits, chosen for production prevalence (auth,
  subprocess, TLS appear in nearly every service) and crisp safe counterparts.

## Per rule (minimal vulnerable + realistic safe + transformation)

| Rule | Realistic safe (silent, verified) | Transformation positive (fires, verified) |
| --- | --- | --- |
| SP101 eval | `ast.literal_eval` wrapper | multiline `eval(\n user_input\n)` |
| SP103 SQL | parameterized `%s` + tuple arg | `.format()`-style interpolation |
| SP138 compare | `hmac.compare_digest` | no-space `token_hash==computed` |
| SP151 subprocess | argv list, no `shell` | `"ls " + target, shell=True` concat |
| SP163 SSL | `create_default_context(cafile=…)` | `unverified_context_creation ()` spacing |

Implementation: `CURATED_NEGATIVES` / `CURATED_POSITIVES` in
`scripts/build_legacy_pattern_contracts.py` (builder fails closed if a curated negative
ever matches or a curated positive does not fire exactly once); manifests regenerated
(`pattern-common`, `pattern-python`, index hashes); debt baseline shrunk via the official
`--update-baseline` (refuses expansion). No detector semantics, severity, or gate
eligibility changed — blocking promotion gates untouched.

Paired regression: `tests/test_q03_walker_pairs.py` scans the exact curated strings as
real files through `scan_repository` — vulnerable fires its rule, safe stays silent for
it, and all five safe files raise zero high/critical findings of any rule.

## Known gaps (documented, not silently fixed)

- Alias evasion (`handler = eval; handler(x)`, `getattr(subprocess, "run")`) stays silent on
  the line-pattern engine for all five rules — expected L0 boundary, recorded here, not
  papered over with renames/exclusions. Structural/data-flow lane or advisory downgrade per
  rule is slice-2+ work with its own precision evidence.
- SP103/SP151 multiline-call transformations do not fire (line-oriented engine); only
  single-line transformation positives were added. Same documented boundary.
- SP101 was already `realistic` before this slice (other contract sources); it still gained
  a reviewed safe counterpart and a production-shaped positive.

## Verification

- `test_legacy_rule_contracts` 6 passed; walker pairs 2 passed; Q01/Q02/importer suites pass
  (39 combined); `rule_assurance --check` gate passed, 635 complete, 0 partial/uncontracted.
- `ruff check .` clean; `git diff --check` clean; self-scan exit 0, 0 app findings.

## Queue

Cohort 1 is closed at 423. Next cohort should start from reproduced noise and the
structural lane (SP108 in `structural-fastapi` needs its own builder recipe), reusing
this recipe: curated safe + transformation cases, walker pairs, baseline shrink, debt
must never grow. Remaining debt: 423 high/critical rules without realistic negatives.

## Slice 4: SP141, SP142, SP143, SP123, SP190 (+ SP141 semantics fix)

| Rule | Realistic safe (silent) | Transformation positive (fires) |
| --- | --- | --- |
| SP141 PRNG seed | `seed(os.urandom(32))` | `seed(time.time())` |
| SP142 ECB | `AES.MODE_GCM` | `AES.MODE_ECB` |
| SP143 salt | `bcrypt.gensalt()` | literal-salt `hashpw` |
| SP123 IV | random `iv` variable | literal `createCipheriv` IV |
| SP190 CORS null | allowlisted origin | `origin: 'null'` |

**SP141 precision fix:** the pattern matched bare `time.time` but not the real-world call
`time.time()` (found by byte-level bisection after a probe misfire). The `random.seed`
branch now accepts optional call parens and `int(…)` nesting: `seed(time.time())`,
`seed(int(time.time()))` fire; `seed(42)` / `seed(os.urandom(32))` stay silent. Existing
`srand`-branch positives untouched. Full 8-case matrix verified.

**SP190 string-literal boundary:** the literal `setHeader("…", "null")` form is silent
because the engine treats in-string matches as data (deliberate doctrine, not a bug to
hot-fix: overriding it needs corpus FP measurement). The `origin: 'null'` form fires and
is the recorded positive; the literal form is a documented FN for the structural lane.

**Walker lesson:** fixtures must use a suffix the rule scans AND the file must parse
(SP190-as-`.py` trips the Python-parser ledger → `parser_limit` → incomplete). The pairs
test is suffix-aware (SP124/SP190 as `.js`).

## Closer (+1): SP158 hardcoded Basic auth

Bearer-from-env safe counterpart (silent) + literal-Basic positive (fires, split-literal
hygiene in builder source). Debt 424 → 423. Contracts, walker pairs (21 rules), assurance
gate, lint, self-scan (exit 0, 0 app) all green. No semantics/severity/eligibility
changes beyond the two documented pattern fixes (SP165, SP141).

## Slice 3: SP122, SP165, SP110, SP124, SP175 (+ SP165 semantics fix)

| Rule | Realistic safe (silent) | Transformation positive (fires) |
| --- | --- | --- |
| SP122 randomness | `token = secrets.token_hex(32)` | `token = random.randint(…)` |
| SP165 Django raw | params-list `.raw("…%s", [id])` | `"…" % name` interpolation |
| SP110 traversal | static `os.path.join` open | `open(f"uploads/{filename}")` |
| SP124 SSRF | static-URL `fetch` | `axios.get(req.params.url)` |
| SP175 header inject | static header assignment | `res.set(…, base + req.query.next)` |

**SP165 precision fix (semantics, not exclusion):** the old pattern `["'][^"']*%[s(]`
fired on the documented-safe params-list form (`raw("…%s", […])`), contradicting the
rule's own remediation note ("Pass query parameters as a list argument"). Pattern is now
`["'][^"']*["']\s*%` (SP103-style: `%` operator outside the string). Verified: old FP
silent, `%`-operator interpolation still fires, existing positives regenerated by the
builder, no other in-repo references. Walker pairs extended (suffix-aware: SP124 scans
as `.js`); all green with zero high/critical on safe files.

**Fixture hygiene:** curated positive strings for SP122/SP175 self-triggered SP122/SP175/
SP110 when scanned as builder source text, so they use split-literal construction (same
idiom as `MANUAL_WITNESSES`); joined values are byte-identical to the verified sources
(manifests unchanged, `--check` current). Self-scan back to exit 0, 0 app findings.

Verification: contracts 6 passed; walker pairs pass; 57 combined tests pass; assurance
gate passed (635 complete); ruff/diff-check clean.

## Slice 2 (this file, second pass): SP104, SP201, SP105, SP144, SP164

| Rule | Realistic safe (silent) | Transformation positive (fires) |
| --- | --- | --- |
| SP104 TLS verify | `Session()` + CA bundle path | `client.get(url, verify=False)` |
| SP201 debug flag | `logging.basicConfig(INFO)` setup | `app.run(debug=True)` |
| SP105 JWT algs | `jwt.decode(t, k, algorithms=["HS256"])` | `algorithms=["none"]` |
| SP144 JWT bypass | `options={"verify_signature": True}` | `options={"verify_signature": False}` |
| SP164 Flask toolbar | `DEBUG_TB_ENABLED = False` | `DEBUG_TB_ENABLED = True` |

All ten sources verified silent/firing before builder edit; manifests regenerated;
baseline shrunk 439 → 434 via `--update-baseline`; walker pairs extended to all 10 rules
(2 tests pass, incl. zero high/critical on all safe files); contract + assurance + lint +
self-scan (0 app) green. No semantics/severity/eligibility changes.
