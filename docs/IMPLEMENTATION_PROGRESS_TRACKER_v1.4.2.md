# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted DEV commit:** `4701705b89a68e1c05eb65007d4aadbc8d92727d`  
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
| Phase 2 Neon DEV | DONE | Real PostgreSQL validation green through Super Admin v1.4.3 |
| Phase 3 Railway DEV | DONE | Exact-commit immutable deployment with readiness/liveness/correlation proof |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Live initial Super Admin identity binding requires the chosen Clerk `user_...` configuration |
| Global USER onboarding v1.4.2 | DONE / DEPLOYED | PR #48 merged; Neon, CI and Railway green |
| Built-in Platform Super Admin full authority v1.4.3 | DONE / DEPLOYED | PR #49 merged; all ACTIVE permissions + future inheritance + Tenant provisioning authority validated |
| Increment G maker-checker | PAUSED | Resume after live initial Clerk Super Admin bootstrap/E2E is green |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Promoted v1.4.2 evidence

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

Frozen invariant:

> **USER onboarding is Platform-global and one-time. Tenant access is authorization assignment, not identity onboarding.**

## 4. Promoted built-in Platform Super Admin authority v1.4.3

Frozen invariant:

> **The built-in Platform Super Admin can initialize and administer the entire Verigence Security platform without requiring another administrator to grant additional roles first.**

Implemented behavior:

1. bootstrap assigns the initial administrator the single built-in `platform.super_admin` role;
2. `platform.super_admin` owns every ACTIVE Security permission;
3. a newly ACTIVE permission is automatically granted to `platform.super_admin`;
4. a permission becoming non-ACTIVE loses its Super Admin grant;
5. Platform-role permissions participate in Tenant authorization;
6. Super Admin can perform Tenant provisioning without a Tenant-specific role assignment;
7. ordinary USERs continue to require Tenant-scoped effective authorization.

Implementation:

- additive migration `0005_super_admin_full_authority.sql`;
- backfill of every ACTIVE permission to `platform.super_admin`;
- PostgreSQL trigger for future permission synchronization;
- Tenant authorization union of Tenant-role grants and active Platform-role grants;
- real PostgreSQL tests for full permission ownership, future permission inheritance/removal and Tenant provisioning without a Tenant role assignment.

Promotion evidence:

```text
Feature head:             5f999948cf1e982d50dbb00699f118e0d5686173
Security CI:              31774336088 — PASS
Real Neon/PostgreSQL:     31774334218 — PASS
PR:                       #49 — MERGED
Promoted DEV commit:      4701705b89a68e1c05eb65007d4aadbc8d92727d
Post-merge Security CI:   31774409815 — PASS
Railway DEV:              31774409818 — PASS
readiness:                PASS
liveness:                 PASS
correlation ID:           PASS
```

## 5. Live initial Super Admin binding — NEXT

No secrets belong in Git.

The Security role/permission data is now fully system-owned. The first real administrator requires no manual permission provisioning after bootstrap.

The chosen Clerk account must be bound using its immutable Clerk User ID:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=user_...
SECURITY_BOOTSTRAP_ENABLED=true
```

Then the authenticated Clerk identity performs the one-time bootstrap claim. Security creates/resolves the global Security USER and assigns `platform.super_admin`. After successful proof, bootstrap is disabled.

Required live proof:

```text
configured Clerk user_...
  -> authenticated Clerk JWT
  -> POST /security/v1/platform/bootstrap/claim
  -> Security USER / CLERK mapping
  -> ACTIVE platform.super_admin assignment
  -> effective full Security authority
  -> Tenant administration without Tenant role assignment
  -> repeat bootstrap denied
  -> SECURITY_BOOTSTRAP_ENABLED=false
```

## 6. Current execution pointer

**NOW:** complete the live initial Clerk Super Admin bootstrap/E2E using the operator-selected Clerk `user_...` identifier.

After that, resume Increment G maker-checker.

Do not reintroduce Tenant-scoped human onboarding or require Tenant role provisioning for the Platform Super Admin after a context reset.
