# Promotion wave B — three bounded ecosystem rules

Date: 2026-09-16 · Status: executable, non-blocking advisory · New rules: **3**

This wave promotes the three `fixture_ready` prototypes from the P2-A research
record into separate executable IDs. The original research candidates remain
research records; the mapping below preserves provenance without reusing a
candidate ID as if it were already shipped.

| Rule | Research candidate | Ecosystem | Boundary | CWE |
| --- | --- | --- | --- | --- |
| SP666 | SP5301 | PHP | Direct `$_FILES[*]['type']` in an `if`/`in_array` upload decision only; content validators, aliases, and computed keys stay silent. | CWE-434 |
| SP667 | SP5951 | Go | Direct sensitive `http.Cookie` literal passed to `SetCookie` without `HttpOnly: true`; helpers and post-construction assignments stay silent. | CWE-1004 |
| SP668 | SP6309 | C/C++ | Direct `argv[index]` in a printf-family format position; safe `%s` data arguments and pointer/alias forms stay silent. | CWE-134 |

Each rule is medium severity and non-blocking until representative shadow
measurements establish precision across real repositories. Every rule has a
complete v2 polarity contract (3 positive, 5 negative, 2 adversarial cases),
official ecosystem/CWE sources, a false-positive boundary, and walker-facing
suffix coverage. The patterns intentionally do not claim full taint or upload
flow reachability.

## Promotion gate

- [x] Duplicate comparison against the existing 638-rule registry.
- [x] Primary source and owning ecosystem documentation recorded.
- [x] Positive, realistic-negative, and adversarial cases pass the real walker.
- [x] Rule assurance inventory reports zero partial/uncontracted debt.
- [ ] Representative-repository shadow precision and runtime delta.
- [ ] Severity or blocking eligibility review.

The remaining 4,997 language-catalog entries stay research-only until this same
evidence boundary is met; quantity alone never turns a hypothesis into a gate.
