# Verigence Security — Implementation Tasks

**Status:** ACTIVE  
**Created:** 2026-08-15

This file records Security implementation work introduced by approved cross-module integration decisions. It does not mark design-only work as implemented.

| ID | Task | Status | Deliverable | Acceptance | Dependency / note |
|---|---|---|---|---|---|
| SEC-INT-001 | Implement platform permissions, service integration and delegated OAuth token exchange | COMPLETE | Security capability for (a) Security user JWTs carrying the Tenant's effective cross-module platform `permissions[]`, (b) Tenant-scoped short-lived `SERVICE` tokens for approved module-owned/admin/background execution and (c) OAuth delegated token exchange/on-behalf-of tokens narrowed to user + integration + requested downstream authority | `src/verigence_security/settings.py`, `tokens.py` and `app.py` implement configuration-driven platform permission bundles, RS256/JWKS issuance, `client_credentials` service tokens and OAuth token exchange with `act.sub` caller attribution; `tests/test_oauth.py` verifies cross-module user permissions, service least privilege, delegated user/Tenant preservation, permission intersection denial, invalid-client denial and JWKS/DI-contract validation; GitHub Actions run `31884091488` passed Ruff and all tests on commit `4692aa6cf51109d9f39416f638ef258a2fcf63ec` | Required by Audit Core `G-01`; design: `docs/SECURITY_CROSS_MODULE_AUTH_DESIGN_v1.0.md`. No private Audit Core<->DI bypass is introduced |
| SEC-RBAC-001 | Implement default PC/TL/PM/CRM templates and Tenant-customizable role management | IN PROGRESS | Security-owned approved default cross-module role catalogue; persistent platform/Tenant role templates; Tenant onboarding seed; Super Admin/Tenant Admin management authorization; effective token resolution from Tenant role configuration | Tests prove: new Tenant receives the approved four defaults; PC default has Audit Core capture/upload plus DI upload/read but no verification-write; TL and PM receive verification capabilities; CRM is DI read-only; Tenant Admin can change only its Tenant operational templates; Super Admin can change any Tenant and future platform defaults; forbidden/unknown/admin permissions are rejected; role changes survive repository/service recreation and change subsequently issued token `permissions[]`; change audit metadata is retained | Design: `docs/SECURITY_DEFAULT_ROLE_TEMPLATES_v1.0.md`; machine defaults: `config/default_role_templates.json`; Audit Core source: `VAC-SD-RBAC-001` + `AUDIT_CORE_SECURITY_CATALOG_v2.1.json` |

## Completion rule

A task becomes COMPLETE only after implementation and the stated positive/negative tests pass. Creating a task/design or committing defaults alone does not complete the implementation.
