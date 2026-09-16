# Promotion wave D — Dart and C#/.NET advisory rules

Date: 2026-09-16 · Status: executable, non-blocking advisory · New rules: **2**

| Rule | Ecosystem | Boundary | CWE |
| --- | --- | --- | --- |
| SP669 | Dart | Literal credential-like keys written through `SharedPreferences`/`prefs.setString`; secure-storage wrappers, reads, aliases, and ordinary settings stay silent. | CWE-922 |
| SP670 | C#/.NET | Direct `DtdProcessing.Parse` or `XmlUrlResolver`/`XmlSecureResolver` configuration; Prohibit/Ignore/null and computed helpers stay silent. | CWE-611 |

Both rules are medium severity, low confidence, and non-blocking until
representative repositories confirm precision. Each has official source claims,
3 positive, 5 negative, 2 adversarial cases, and real-walker coverage.
