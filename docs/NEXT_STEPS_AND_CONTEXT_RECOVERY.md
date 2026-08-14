# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4  
**Last updated:** 2026-08-14

## 1. Governing recovery rule

Implementation is grounded in approved/versioned repository artifacts, not chat reconstruction.

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`;
3. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`;
4. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
5. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
6. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`;
7. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
8. `docs/IMPLEMENTATION_STATUS.md`;
9. current `dev`, open Security PRs and CI/Railway state.

## 2. Invariants that must survive every reset

```text
Human onboarding          = Platform-global, once per normal USER
Clerk                     = authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Platform Super Admin      = built-in initial system administrator with full authority
Initial administrator     = operator-selected immutable Clerk user_... provisioned as setup data
```

The first environment administrator is exceptional installation data, not a normal onboarding event.

`platform.super_admin` owns every ACTIVE Security permission, automatically inherits future ACTIVE permissions and can administer Tenant authorization without a Tenant-specific role assignment.

## 3. Current promoted baseline

```text
DEV commit: b3c9994c420a261ef55ad402f1d8219651eebdb7
```

The deployed baseline includes global USER onboarding v1.4.2 and full Super Admin authority v1.4.3.

Latest Super Admin authority evidence:

```text
PR #49:                  MERGED
Feature Security CI:     31774336088 — PASS
Feature Neon/PostgreSQL: 31774334218 — PASS
Post-merge Security CI:  31774409815 — PASS
Railway DEV:             31774409818 — PASS
readiness/liveness/correlation: PASS
```

## 4. Current workstream

**NOW:** v1.4.4 initial Platform Super Admin system provisioning.

DEV selected Clerk identity:

```text
user_3HtNkIWp32cD9HC7KzDbZdJkr2h
```

Required sequence:

```text
feature/super-admin-system-provisioning-v1.4.4
   ↓
Security CI + Neon regression
   ↓
merge to dev with [provision-initial-super-admin] marker
   ↓
controlled provisioning job uses selected Clerk user_...
   ↓
ACTIVE Security USER + CLERK mapping + platform.super_admin
   ↓
verify complete ACTIVE permission coverage
   ↓
Railway DEV remains green
   ↓
selected person authenticates normally with Clerk
   ↓
Security Platform Admin login/full-authority proof
   ↓
resume Increment G
```

Fresh installation no longer requires the person to execute `/security/v1/platform/bootstrap/claim` simply to initialize the platform. The historical claim path stays disabled unless a specific compatibility procedure requires it.

## 5. Initial Super Admin rule

Do not create a circular provisioning dependency.

The operator supplies only the immutable Clerk User ID. Security creates the initial global USER and one built-in role assignment:

```text
platform.super_admin
```

No Tenant membership, Tenant role, onboarding key or local credential is required for this initial system administrator.

The provisioning operation is serialized and idempotent for the same already-bound Super Admin. It fails closed rather than replacing a different active Super Admin.

## 6. Global USER onboarding rule

Do not reconstruct the retired Tenant-scoped identity onboarding model.

Normal people are onboarded once as global Security USERs. The same `user_id` can be assigned different authorization in many Tenants without another onboarding event.

Security validates the Platform onboarding key before Clerk provisioning for normal USER onboarding, and only Security Admin activation changes a normal onboarding USER to ACTIVE.

## 7. Identity boundary

Clerk continues to own credentials, MFA, verification, recovery and authentication sessions.

Initial provisioning only establishes the Security-side identity mapping and authorization. It does not mint a Clerk session or bypass Clerk authentication.

After provisioning, the selected Super Admin authenticates normally with Clerk. Security verifies the Clerk JWT, resolves its `sub` to the provisioned Security USER and issues the Verigence Platform Admin token from Security-owned authorization data.

## 8. Promotion discipline

```text
feature/*
   ↓ Security CI + applicable real Neon/PostgreSQL
  dev
   ↓ exact-commit Security CI
controlled setup data provisioning when explicitly marked
   ↓
immutable GHCR image -> Railway DEV
   ↓ readiness + liveness + correlation
```

Do not move to Increment G until initial DEV Super Admin provisioning and normal Clerk -> Security login proof are green.
