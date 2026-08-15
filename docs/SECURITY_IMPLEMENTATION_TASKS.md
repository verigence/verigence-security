# Verigence Security — Implementation Tasks

**Status:** ACTIVE  
**Created:** 2026-08-15

This file records Security implementation work introduced by approved cross-module integration decisions. It does not mark design-only work as implemented.

| ID | Task | Status | Deliverable | Acceptance | Dependency / note |
|---|---|---|---|---|---|
| SEC-INT-001 | Implement platform permissions, service integration and delegated OAuth token exchange | COMPLETE | Security capability for (a) Security user JWTs carrying the Tenant's effective cross-module platform `permissions[]`, (b) Tenant-scoped short-lived `SERVICE` tokens for approved module-owned/admin/background execution and (c) OAuth delegated token exchange/on-behalf-of tokens narrowed to user + integration + requested downstream authority | `src/verigence_security/settings.py`, `tokens.py` and `app.py` implement configuration-driven platform permission bundles, RS256/JWKS issuance, `client_credentials` service tokens and OAuth token exchange with `act.sub` caller attribution; `tests/test_oauth.py` verifies cross-module user permissions, service least privilege, delegated user/Tenant preservation, permission intersection denial, invalid-client denial and JWKS/DI-contract validation; GitHub Actions run `31884091488` passed Ruff and all tests on commit `4692aa6cf51109d9f39416f638ef258a2fcf63ec` | Required by Audit Core `G-01`; design: `docs/SECURITY_CROSS_MODULE_AUTH_DESIGN_v1.0.md`. Exact business role/permission catalogue remains configuration input; no unapproved permission bundle is hard-coded and no private Audit Core<->DI bypass is introduced |

## Completion rule

`SEC-INT-001` becomes COMPLETE only after implementation and the stated positive/negative integration tests pass. Creating this task/design does not complete it.
