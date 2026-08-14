# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3  
**Last updated:** 2026-08-14

## 1. Governing recovery rule

Implementation is grounded in approved/versioned repository artifacts, not chat reconstruction.

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`;
3. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
4. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
5. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`;
6. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
7. `docs/IMPLEMENTATION_STATUS.md`;
8. current `dev`, open Security PRs and CI/Railway state.

## 2. Invariants that must survive every reset

```text
Human onboarding          = Platform-global, once per person
Clerk                     = authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Platform Super Admin      = built-in initial system administrator with full authority
```

`platform.super_admin` owns every ACTIVE Security permission, automatically inherits future ACTIVE permissions and can administer Tenant authorization without a Tenant-specific role assignment.

## 3. Current promoted baseline

```text
DEV commit: 4701705b89a68e1c05eb65007d4aadbc8d92727d
```

Promotion evidence for the latest Super Admin authority clarification:

```text
PR #49:                  MERGED
Feature Security CI:     31774336088 — PASS
Feature Neon/PostgreSQL: 31774334218 — PASS
Post-merge Security CI:  31774409815 — PASS
Railway DEV:             31774409818 — PASS
readiness/liveness/correlation: PASS
```

The earlier global USER onboarding v1.4.2 promotion through PR #48 remains valid historical evidence.

## 4. Current workstream

**NOW:** live initial Clerk Super Admin bootstrap/E2E.

The built-in role and permission data are already deployed. No administrator must provision extra roles before the first Super Admin can operate the system.

Required sequence:

```text
operator-selected Clerk user_...
   ↓
configure SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID
   ↓
temporarily enable SECURITY_BOOTSTRAP_ENABLED
   ↓
authenticated Clerk JWT
   ↓
POST /security/v1/platform/bootstrap/claim
   ↓
Security global USER + CLERK mapping
   ↓
ACTIVE platform.super_admin assignment
   ↓
verify full Platform + Tenant administration authority
   ↓
prove repeated bootstrap is denied
   ↓
disable bootstrap
   ↓
resume Increment G
```

## 5. Super Admin rule

Do not create a circular provisioning dependency.

Security bootstrap assigns one built-in role:

```text
platform.super_admin
```

That one role supplies full effective authority through system-owned permission data. Do not add redundant Platform/Tenant roles simply to reproduce the same access.

## 6. Global USER onboarding rule

Do not reconstruct the retired Tenant-scoped identity onboarding model.

A person has one global Security USER and one Clerk mapping. The same `user_id` can be assigned different authorization in many Tenants without another onboarding event.

Security validates the Platform onboarding key before Clerk provisioning, and only Security Admin activation changes a normal onboarding USER to ACTIVE.

## 7. Live initial administrator dependency

No secret values belong in Git or chat.

The only non-secret identity value still required for the live bootstrap is the immutable Clerk User ID selected by the operator:

```text
user_...
```

The Clerk User ID selects the initial administrator identity. The deployed built-in Security role determines its authority.

## 8. Promotion discipline

```text
feature/*
   ↓ Security CI + applicable real Neon/PostgreSQL
  dev
   ↓ exact-commit Security CI
immutable GHCR image
   ↓
Railway DEV
   ↓ readiness + liveness + correlation
```

Do not move to Increment G until the live initial Clerk bootstrap is green.
