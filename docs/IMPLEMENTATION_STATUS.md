# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3  
**Last updated:** 2026-08-14

Detailed execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Current promoted baseline

```text
4701705b89a68e1c05eb65007d4aadbc8d92727d
```

This `dev` baseline includes:

- Security CI, Neon/PostgreSQL and Railway DEV foundations;
- USER device/access-session security controls;
- Platform Admin Control Plane implementation;
- Clerk-backed Platform Super Admin bootstrap/login boundary;
- global one-time USER onboarding and Security-owned USER lifecycle;
- global onboarding key;
- Tenant authorization without a Tenant-membership prerequisite;
- same USER authorization across multiple Tenants;
- per-user/per-Tenant authorization versioning;
- built-in `platform.super_admin` full effective authority;
- automatic future ACTIVE-permission inheritance for Super Admin;
- Super Admin Tenant provisioning without a Tenant-specific role assignment;
- immutable GHCR -> Railway exact-digest deployment.

## 2. Global USER onboarding v1.4.2 — DONE / DEPLOYED

```text
PR #48:                  MERGED
Feature Neon:            31768537758 — PASS
Post-merge Security CI:  31768624655 — PASS
Railway DEV:             31768624692 — PASS
readiness/liveness/correlation: PASS
```

Governing invariant:

> **A human is onboarded once at Platform level. Tenant access is authorization assignment, not identity onboarding.**

## 3. Built-in Platform Super Admin v1.4.3 — DONE / DEPLOYED

Governing invariant:

> **One `platform.super_admin` assignment gives the initial administrator full effective Security authority. No second administrator or Tenant-role bootstrap is required.**

Implementation includes:

- migration `0005_super_admin_full_authority.sql`;
- every ACTIVE Security permission granted to `platform.super_admin`;
- automatic synchronization of future permission activation/retirement;
- Platform-role permission participation in Tenant authorization;
- Super Admin Tenant provisioning without Tenant-specific role assignment;
- PostgreSQL acceptance tests for these invariants.

Promotion evidence:

```text
PR #49:                  MERGED
Feature head:            5f999948cf1e982d50dbb00699f118e0d5686173
Feature Security CI:     31774336088 — PASS
Feature Neon:            31774334218 — PASS
Promoted DEV commit:     4701705b89a68e1c05eb65007d4aadbc8d92727d
Post-merge Security CI:  31774409815 — PASS
Railway DEV:             31774409818 — PASS
readiness/liveness/correlation: PASS
```

## 4. Identity boundary

Clerk owns human credentials, MFA, recovery and authentication sessions.

Security owns:

- global USER record and lifecycle;
- Clerk-to-Security USER mapping;
- Platform and Tenant authorization;
- Super Admin role assignment and authority data;
- Security access/session decisions.

The initial administrator is bound once through the Clerk bootstrap flow. The single `platform.super_admin` assignment supplies full authority automatically.

## 5. NEXT — live initial Super Admin bootstrap

The operator-selected Clerk account must be identified by its immutable Clerk User ID:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=user_...
```

After configuration, enable bootstrap temporarily, execute the authenticated one-time claim, verify the Security USER/Clerk mapping and full effective authority, prove a repeated claim is denied, then disable bootstrap.

No password, Clerk session JWT or Clerk secret belongs in chat or Git.

## 6. Other deferred work

Still unresolved unless a later tracker says otherwise:

- complete SEC-032 Tenant activation prerequisite catalogue;
- persistent cross-replica idempotency store;
- device `BLOCKED` vs `REVOKED` business semantics;
- legacy v1.3 lifecycle route shapes dependent on unavailable v1.3 OpenAPI;
- exact recent-MFA freshness threshold for privileged operations;
- broader Clerk webhook lifecycle semantics;
- SYSTEM/SERVICE_INTEGRATION issuance;
- retention/offboarding execution;
- overlapping JWKS rotation;
- WPM catalogue;
- UAT/Production readiness.
