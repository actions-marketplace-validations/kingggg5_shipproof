# Q04 evaluation — corpus, harness, and first inventory (2026-09-15)

## Corpus: 10 repos, 5 ecosystems (acceptance: ≥10, 5 ✓)

| Repo | Ecosystem | Kind | Class | Split | Rev | License |
| --- | --- | --- | --- | --- | --- | --- |
| express | javascript | library | clean | development | 023767fe | MIT |
| flask | python | library | clean | development | d318b683 | BSD-3-Clause |
| requests | python | library | clean | development | 8f8b212d | Apache-2.0 |
| juice-shop | javascript | vulnerable-app | vuln | development | 1618a611 | MIT |
| dvwa | php | vulnerable-app | vuln | development | 5d5c76cc | GPL-3.0-or-later |
| nodegoat | javascript | vulnerable-app | vuln | development | c5cb68a7 | Apache-2.0 |
| gin | go | service | clean | development | 75ccf94d | MIT |
| click | python | cli | clean | development | 934813e4 | BSD-3-Clause |
| preact | javascript | frontend | clean | **holdout** | ccd1e71e | MIT |
| petclinic | java | service | clean | **holdout** | 818c4136 | Apache-2.0 |

All pins verified by fetch + license-file check at run time (fail-closed `prepare`).
Missing vs plan: monorepo and generated-code kinds — next corpus extension.

## Development-split inventory (measured 2026-09-15, Windows/py3.12)

| Repo | Files | KLOC | App findings | By severity | Dup rate |
| --- | --- | --- | --- | --- | --- |
| express | 180 | 26.7 | 2 | high 1, low 1 | 0.0 |
| flask | 224 | 38.5 | 6 | med 2, low 4 | 0.0 |
| requests | 98 | 22.0 | 0 | — | 0.0 |
| juice-shop | 1112 | 268.6 | 179 | crit 29, high 116, med 32, low 2 | 0.123 |
| dvwa | 230 | 29.8 | 76 | crit 11, high 29, med 36 | 0.040 |
| nodegoat | 95 | 46.4 | 25 | high 12, med 13 | 0.040 |
| gin | 113 | 24.0 | 18 | high 14, med 4 | 0.111 |
| click | 123 | 26.0 | 24 | high 4, med 2, low 18 | 0.542 |

Holdout probe (measurement only, `holdout_used` flagged, never tuning): preact 303
files / 53 app (high 44, med 9, top SP423/SP203/SP147); petclinic 111 files / 57 app
(crit 1, high 12, med 44, top SP302/SP203).

## What is NOT claimed

- Every finding above is `unreviewed`. Precision, FP/KLOC, and recall are **unknown**
  until the Q04 label protocol produces confirmed two-reviewer labels (kappa ≥ 0.8) and
  independent ground-truth files for the vulnerable apps. The harness reports
  `reviewed_confirmed/provisional/unreviewed`, per-proof breakdowns, duplicate rates,
  and recall-only-with-ground-truth today; cohort promotion gates must cite those
  fields with sample counts, never bare finding counts.

## Harness changes (this milestone)

- `eval-realworld.py`: `ecosystem`/`kind`/`split` manifest fields (validated, defaulted);
  development-only default with `--include-holdout` audit flag; KLOC denominators;
  `by_proof_level` + app split; duplicate-fingerprint groups/rate on full findings;
  `known_defect_recall` via `benchmarks/ground-truth/<repo>.json` (unknown when absent).
- `finding_labels.py`: `reviewer` + `status` (legacy records stay provisional), per-reviewer
  dedupe, confirmed-first indexing, `agreement_summary` (Cohen's kappa).
- New tests: manifest count/splits, split/kind rejection, recall unknown/measured,
  agreement (5 tests). Existing clean-corpus label tests still pass unchanged.
