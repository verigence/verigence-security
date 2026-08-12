# Approved Security v1.3 Source Reference

This implementation commit was reviewed against the approved Security v1.3 solution artifacts. To avoid silently regenerating or altering a normative API specification during code check-in, the approved OpenAPI is referenced by its verified digest rather than replaced by a newly generated copy.

| Approved artifact | SHA-256 | Repository handling |
|---|---|---|
| `SECURITY_OPENAPI_v1.3.yaml` | `07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37` | Reviewed against implementation; authoritative copy remains in the approved Security v1.3 solution source |
| `SECURITY_POSTGRESQL_SCHEMA_v1.3.sql` | `175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d` | Committed byte-identically as `migrations/0001_security_baseline_v1.3.sql` |
| `SECURITY_DECISION_REGISTER_v1.3.md` | `a05b5e0f04cc63e5d76f54a3a120161aa8ce2172e7c810534c36445e85608070` | Committed byte-identically |
| `SECURITY_CORRELATION_STANDARD_v1.3.md` | `fa0f0886eaf6482e52c00ea612550d0674e5ed7b099bc6e9e2e71a84c1a1e1e0` | Committed byte-identically |
| `SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md` | `0c7c83ae08d4488951ff90e8c95c34eff7220b55da17329dc65699f91288cceb` | Committed byte-identically |

Any future copy of the approved OpenAPI added to this repository must match the digest above or be accompanied by an explicitly approved Security design-version change.
