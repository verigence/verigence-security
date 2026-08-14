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
Platform Super Admin      = built-in initial system administrator
```

The built-in `platform.super_admin` is sufficient to initialize the platform. It owns every ACTIVE Security permission and does not need separate Tenant-role or additional Platform-role provisioning before it can administer the system.

## 3. Current promoted baseline

```text
DEV commit: 9856d7398e0af9937506033e1cf60d69d91e2d71
```

This includes the v1.4.2 global USER onboarding correction.

Promotion evidence:

```text
PR #48:                  MERGED
Neon/PostgreSQL:         31768537758 — PASS
Post-merge Security CI: 31768624655 — PASS
Railway DEV:            31768624692 — PASS
```

## 4. Current workstream

**NOW:** built-in Platform Super Admin full-authority clarification.

Feature branch:

```text
feature/super-admin-full-authority-v1.4.3
```

Required sequence:

```text
migration 0005
   ↓
backfill all ACTIVE permissions to platform.super_admin
   ↓
automatic future permission synchronization
   ↓
include Platform-role grants in Tenant authorization
   ↓
real Neon/PostgreSQL acceptance tests
   ↓
Security CI
   ↓
PR -> dev
   ↓
Railway DEV exact-digest proof
   ↓
live initial Clerk Super Admin binding
```

## 5. Super Admin rule

Do not create a circular provisioning dependency.

The first administrator must not require another administrator to grant it additional roles.

Security bootstrap assigns one role:

```text
platform.super_admin
```

That role supplies full effective authority through system-owned permission data.

New ACTIVE Security/module permissions must automatically become effective for the Super Admin.

Platform Super Admin must be able to configure Tenants and Tenant RBAC without a Tenant-specific role assignment.

Ordinary USERs still require Tenant-scoped effective authorization.

## 6. Global USER onboarding rule

Do not reconstruct the retired Tenant-scoped identity onboarding model.

A person has one global Security USER and one Clerk mapping. The same `user_id` can be assigned different authorization in many Tenants without another onboarding event.

Security validates the Platform onboarding key before Clerk provisioning, and only Security Admin activation changes a normal onboarding USER to ACTIVE.

## 7. Live initial administrator dependency

No secret values belong in Git.

The operator-selected Clerk account still needs to be bound once using its immutable Clerk User ID:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=user_...
```

The Clerk User ID only selects the initial administrator identity. The built-in Security role determines its authority.

## 8. Promotion discipline

```text
feature/*
   ↓ Security CI + real Neon/PostgreSQL
  dev
   ↓ exact-commit Security CI
immutable GHCR image
   ↓
Railway DEV
   ↓ readiness + liveness + correlation
```

Do not move to Increment G until the current Super Admin authority correction and live initial Clerk bootstrap are green.
