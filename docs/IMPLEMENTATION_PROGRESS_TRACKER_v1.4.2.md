# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted DEV commit:** `9856d7398e0af9937506033e1cf60d69d91e2d71`  
**Branch under validation:** `feature/super-admin-full-authority-v1.4.3`  
**Date:** 2026-08-14

## 1. Implementation authorities

Read/apply in this order when decisions conflict:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md` for built-in Super Admin authority;
3. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
4. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk ownership/authentication rules;
5. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin Control Plane scope;
6. Security v1.3 normative artifacts for unchanged runtime scope;
7. this tracker for current execution/evidence.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build and dependency checks enforced |
| Phase 2 Neon DEV | DONE | Real PostgreSQL validation available and green for v1.4.2 |
| Phase 3 Railway DEV | DONE | Exact-commit immutable deployment with readiness/liveness/correlation proof |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Live initial Super Admin identity binding still requires the chosen Clerk `user_...` configuration |
| Global USER onboarding v1.4.2 | DONE / DEPLOYED | PR #48 merged to `dev`; Neon, post-merge CI and Railway all green |
| Built-in Platform Super Admin full authority | NOW | Data-driven full authority + automatic future permission inheritance + Tenant provisioning authority under validation |
| Increment G maker-checker | PAUSED | Resume after Super Admin authority correction and live initial Clerk bootstrap are green |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Promoted v1.4.2 evidence

Global USER onboarding v1.4.2 was completed and promoted through PR #48.

```text
Feature head:             f6dca3ef86c664b49fcd400e1bca099ceced0a0d
Real Neon/PostgreSQL:     31768537758 — PASS
PR:                       #48 — MERGED
Promoted DEV commit:      9856d7398e0af9937506033e1cf60d69d91e2d71
Post-merge Security CI:   31768624655 — PASS
Railway DEV:              31768624692 — PASS
readiness:                PASS
liveness:                 PASS
correlation ID:           PASS
```

The promoted model is:

> **USER onboarding is Platform-global and one-time. Tenant access is authorization assignment, not identity onboarding.**

## 4. Current clarification — built-in Platform Super Admin

Frozen invariant:

> **The built-in Platform Super Admin must be able to initialize and administer the entire Verigence Security platform without requiring another administrator to grant additional roles first.**

Required behavior:

1. bootstrap assigns the initial administrator the single built-in `platform.super_admin` role;
2. `platform.super_admin` owns every ACTIVE Security permission;
3. when a new permission becomes ACTIVE it is automatically granted to `platform.super_admin`;
4. when a permission becomes non-ACTIVE its Super Admin grant is removed;
5. Platform-role permissions participate in Tenant authorization;
6. a Super Admin can perform Tenant provisioning without a Tenant-specific role assignment;
7. ordinary USERs continue to require Tenant-scoped effective authorization.

Implementation branch:

```text
feature/super-admin-full-authority-v1.4.3
```

Implementation includes:

- additive migration `0005_super_admin_full_authority.sql`;
- backfill of every ACTIVE permission to `platform.super_admin`;
- PostgreSQL trigger that keeps future ACTIVE permission grants synchronized automatically;
- effective authorization union of Tenant-role grants and active Platform-role grants;
- real PostgreSQL tests proving full permission ownership, future permission inheritance/removal and Tenant provisioning without Tenant role assignment;
- Neon workflow coverage for migration 0005 and the new tests.

## 5. Acceptance evidence required for the current branch

Do not merge until all are green on the exact feature head:

- Security CI;
- migration 0005 applied successfully on Neon DEV;
- Super Admin owns all ACTIVE permissions;
- new ACTIVE permission is auto-granted;
- retired permission is removed from Super Admin grants;
- Super Admin Tenant administration succeeds without a Tenant role assignment;
- historical Phase 5 PostgreSQL tests remain green.

Evidence:

```text
Feature head:             PENDING
Security CI:              PENDING
Real Neon/PostgreSQL:     PENDING
PR:                       PENDING
Promoted DEV commit:      PENDING
Post-merge Security CI:   PENDING
Railway DEV:              PENDING
```

## 6. Live initial Super Admin binding

No secrets belong in Git.

The Security role/permission data is system-owned. The first real administrator does not require manual permission provisioning after bootstrap.

The live Clerk identity still needs to be bound to the Security bootstrap through the immutable Clerk User ID:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=user_...
```

After successful one-time bootstrap claim, Security creates/resolves the Security USER and assigns `platform.super_admin`. The data-driven role then supplies full authority automatically.

## 7. Current execution pointer

```text
Super Admin full-authority branch
  -> Security CI + real Neon/PostgreSQL
  -> PR -> dev
  -> exact-commit Security CI
  -> immutable GHCR image -> Railway DEV
  -> readiness/liveness/correlation
  -> configure chosen Clerk user_...
  -> live one-time Super Admin bootstrap claim
  -> verify full effective authority
  -> disable bootstrap
  -> resume Increment G
```

Do not reintroduce Tenant-scoped human onboarding or require Tenant role provisioning for the Platform Super Admin after a context reset.
