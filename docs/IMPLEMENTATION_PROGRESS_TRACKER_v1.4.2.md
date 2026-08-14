# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted DEV commit:** `b3c9994c420a261ef55ad402f1d8219651eebdb7`  
**Current branch under validation:** `feature/super-admin-system-provisioning-v1.4.4`  
**Date:** 2026-08-14

## 1. Implementation authorities

Read/apply in this order when decisions conflict:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md` for fresh-environment initial administrator provisioning;
3. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md` for built-in Super Admin authority;
4. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for normal global USER onboarding/lifecycle;
5. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk authentication ownership;
6. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin Control Plane scope;
7. Security v1.3 normative artifacts for unchanged runtime scope;
8. this tracker for current execution/evidence.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build and dependency checks enforced |
| Phase 2 Neon DEV | DONE | Real PostgreSQL validation green through Super Admin v1.4.3 |
| Phase 3 Railway DEV | DONE | Exact-commit immutable deployment with readiness/liveness/correlation proof |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Clerk remains the human authentication provider |
| Global USER onboarding v1.4.2 | DONE / DEPLOYED | PR #48 merged; Neon, CI and Railway green |
| Built-in Platform Super Admin authority v1.4.3 | DONE / DEPLOYED | PR #49 merged; full current/future permission authority validated |
| Initial Super Admin system provisioning v1.4.4 | UNDER VALIDATION | Operator-selected Clerk User ID is seeded as the first Security Super Admin without a manual claim |
| Increment G maker-checker | PAUSED | Resume after v1.4.4 provisioning is promoted and the provisioned Clerk identity can complete normal Clerk -> Security login |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Promoted global USER onboarding v1.4.2

```text
Feature head:             f6dca3ef86c664b49fcd400e1bca099ceced0a0d
Real Neon/PostgreSQL:     31768537758 — PASS
PR:                       #48 — MERGED
Promoted DEV commit:      9856d7398e0af9937506033e1cf60d69d91e2d71
Post-merge Security CI:   31768624655 — PASS
Railway DEV:              31768624692 — PASS
readiness/liveness/correlation: PASS
```

Frozen invariant:

> **USER onboarding is Platform-global and one-time. Tenant access is authorization assignment, not identity onboarding.**

## 4. Promoted built-in Platform Super Admin authority v1.4.3

```text
Feature head:             5f999948cf1e982d50dbb00699f118e0d5686173
Security CI:              31774336088 — PASS
Real Neon/PostgreSQL:     31774334218 — PASS
PR:                       #49 — MERGED
Promoted DEV code commit: 4701705b89a68e1c05eb65007d4aadbc8d92727d
Post-merge Security CI:   31774409815 — PASS
Railway DEV:              31774409818 — PASS
readiness/liveness/correlation: PASS
```

The built-in `platform.super_admin` owns every ACTIVE Security permission, inherits future ACTIVE permissions automatically and can administer Tenant authorization without a Tenant-specific role.

## 5. Current clarification — initial system administrator v1.4.4

Fresh installation no longer requires a human-operated first-user claim.

The operator selects the initial Clerk identity by immutable Clerk User ID. The controlled provisioning job creates, in one transaction:

```text
Security USER principal = ACTIVE
Security global USER    = ACTIVE
External identity       = CLERK / configured user_... / ACTIVE
Platform role           = platform.super_admin / ACTIVE / BOOTSTRAP
Audit record            = platform.super_admin.system_provision
```

No Tenant membership, Tenant role or local password credential is created.

DEV selected Clerk User ID:

```text
user_3HtNkIWp32cD9HC7KzDbZdJkr2h
```

This identifier is environment-specific nonsecret deployment configuration. Clerk passwords, session tokens and secret keys remain outside Git.

The fresh-installation v1.4.4 path supersedes the manual `/platform/bootstrap/claim` requirement. The historical claim implementation remains disabled unless an explicit compatibility procedure enables it.

## 6. v1.4.4 acceptance gates

Before merge/promotion:

- Security CI green on the exact feature head;
- unit tests prove creation, idempotency, fail-closed conflict handling and Clerk `user_` validation;
- existing Neon/PostgreSQL Phase 5 suite remains green;
- design/static integrity remains green.

After merge to `dev` using the controlled provisioning marker:

- exact-commit Security CI green;
- DEV provisioning workflow creates/binds the selected Clerk identity;
- verification proves ACTIVE principal/USER/external identity/Super Admin role;
- verification proves zero missing ACTIVE permissions for `platform.super_admin`;
- Railway DEV exact-digest deployment remains green;
- readiness/liveness/correlation checks remain green.

## 7. Current execution pointer

```text
feature/super-admin-system-provisioning-v1.4.4
  -> Security CI + existing Neon/PostgreSQL regression
  -> PR -> dev with [provision-initial-super-admin] marker
  -> exact-commit Security CI
  -> one-time controlled DEV Super Admin data provisioning
  -> Railway DEV exact-digest deployment
  -> readiness/liveness/correlation
  -> normal Clerk authentication for the provisioned Super Admin
  -> Security Platform Admin login/full-authority proof
  -> resume Increment G
```

Do not reintroduce Tenant-scoped human onboarding, Tenant membership for USER onboarding, or redundant Tenant-role provisioning for the Platform Super Admin.
