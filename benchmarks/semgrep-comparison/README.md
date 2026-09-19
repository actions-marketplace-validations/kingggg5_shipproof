# Caller-supplied comparison ruleset

`rules.yml` is an original, repository-authored Semgrep config for the local fixture corpora. It exists so a Linux comparison run can use `--semgrep-config` without downloading or copying a third-party ruleset.

ShipProof never bundles Semgrep, never fetches rules at scan time, and never copies license-restricted detector text. Supply this file (or another file you own) explicitly:

```bash
python benchmarks/head_to_head.py \
  fixtures/vulnerable-node-api \
  fixtures/vulnerable-python-api \
  fixtures/node-taint-crossfile \
  fixtures/adversarial-node \
  fixtures/secure-node-api \
  fixtures/node-secure-crossfile \
  --semgrep-config benchmarks/semgrep-comparison/rules.yml \
  --repeat 3 --format json
```

CI runs that comparison only when the workflow input `run-semgrep` is true. File-level and line-level scores describe these corpora and this config only.
