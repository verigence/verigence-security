# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3  
**Last updated:** 2026-08-14

Detailed current execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Current promoted baseline

```text
9856d7398e0af9937506033e1cf60d69d91e2d71
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
- immutable GHCR -> Railway exact-digest deployment.

Global USER onboarding v1.4.2 promotion evidence:

```text
PR #48:                  MERGED
Feature Neon:            31768537758 — PASS
Post-merge Security CI:  31768624655 — PASS
Railway DEV:             31768624692 — PASS
readiness/liveness/correlation: PASS
```

## 2. Current clarification — built-in Platform Super Admin

A new Verigence installation must have one initial administrator capable of provisioning the rest of the system.

The governing invariant is:

> **One `platform.super_admin` assignment gives the initial administrator full effective Security authority. No second administrator or Tenant-role bootstrap is required.**

The current implementation branch is:

```text
feature/super-admin-full-authority-v1.4.3
```

It adds:

- migration `0005_super_admin_full_authority.sql`;
- backfill of every ACTIVE Security permission to `platform.super_admin`;
- automatic future permission synchronization through a PostgreSQL trigger;
- removal of Super Admin grants when a permission becomes non-ACTIVE;
- Platform-role permission participation in Tenant authorization;
- Super Admin Tenant provisioning without Tenant-specific role assignment;
- Neon/PostgreSQL acceptance tests for the invariant.

This remains data-driven: the user receives one built-in `platform.super_admin` role rather than redundant assignments to every other role.

## 3. Identity boundary

Clerk continues to own human credentials, MFA, recovery and authentication sessions.

Security owns:

- global USER record and lifecycle;
- Clerk-to-Security USER mapping;
- Platform and Tenant authorization;
- Super Admin role assignment;
- Security access/session decisions.

The first real administrator is bound once through the Clerk bootstrap flow. After the successful claim, the single `platform.super_admin` assignment supplies full authority automatically.

## 4. Live configuration still required

No secret values belong in Git.

Live Clerk/global onboarding requires the configured Clerk verification and Backend API secrets already documented in the governing designs.

The initial Super Admin binding still requires the immutable Clerk User ID selected by the operator:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=user_...
```

The ID identifies which Clerk account becomes the initial Security Super Admin; it does not determine permissions. Permissions come from the built-in system role/data.

## 5. Current execution direction

```text
Super Admin authority branch
       ↓
Security CI + real Neon/PostgreSQL
       ↓
PR -> dev
       ↓
exact-commit CI
       ↓
immutable GHCR image -> Railway DEV
       ↓
health/correlation proof
       ↓
live Clerk Super Admin bootstrap
       ↓
verify full effective authority
       ↓
resume Increment G
```

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
