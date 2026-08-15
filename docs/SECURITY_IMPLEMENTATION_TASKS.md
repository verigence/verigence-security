# Verigence Security — Implementation Tasks

**Status:** ACTIVE  
**Created:** 2026-08-15

This file records Security implementation work introduced by approved cross-module integration decisions. It does not mark design-only work as implemented.

| ID | Task | Status | Deliverable | Acceptance | Dependency / note |
|---|---|---|---|---|---|
| SEC-INT-001 | Implement service integration and delegated OAuth token exchange | NOT STARTED | Security capability for (a) Tenant-scoped short-lived `SERVICE` tokens for approved module-owned/admin/background execution and (b) OAuth delegated token exchange/on-behalf-of tokens for user-driven downstream calls | Controlled tests prove: Audit Core service identity can obtain only its allowed DI permissions; a user-driven exchange preserves user/Tenant attribution and cannot exceed the intersection of user + Audit Core + requested authority; denied exchange does not fall back to service identity; issued JWTs validate through Security JWKS and are accepted by the current DI JWT contract | Required by Audit Core `G-01`; design: `docs/SECURITY_CROSS_MODULE_AUTH_DESIGN_v1.0.md`. Must not introduce a private Audit Core<->DI bypass |

## Completion rule

`SEC-INT-001` becomes COMPLETE only after implementation and the stated positive/negative integration tests pass. Creating this task/design does not complete it.
