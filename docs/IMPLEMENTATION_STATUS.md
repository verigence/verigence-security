# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4  
**Last updated:** 2026-08-14

Detailed execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Current promoted baseline

```text
b3c9994c420a261ef55ad402f1d8219651eebdb7
```

This `dev` baseline includes:

- Security CI, Neon/PostgreSQL and Railway DEV foundations;
- USER device/access-session security controls;
- Platform Admin Control Plane implementation;
- Clerk-backed human authentication boundary;
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

Promotion evidence:

```text
PR #49:                  MERGED
Feature head:            5f999948cf1e982d50dbb00699f118e0d5686173
Feature Security CI:     31774336088 — PASS
Feature Neon:            31774334218 — PASS
Promoted DEV code:       4701705b89a68e1c05eb65007d4aadbc8d92727d
Post-merge Security CI:  31774409815 — PASS
Railway DEV:             31774409818 — PASS
readiness/liveness/correlation: PASS
```

## 4. Initial Super Admin provisioning v1.4.4 — UNDER VALIDATION

Fresh Verigence installation now treats the initial administrator as controlled system setup data.

The operator selects one immutable Clerk User ID. Security provisions that identity once as:

```text
ACTIVE global Security USER
ACTIVE CLERK external identity
ACTIVE platform.super_admin assignment
BOOTSTRAP assignment source
Platform audit record
```

No Tenant membership, Tenant role or local password credential is created.

DEV selected Clerk identity:

```text
user_3HtNkIWp32cD9HC7KzDbZdJkr2h
```

The controlled provisioning service is idempotent for the same already-bound Super Admin and fails closed if a different active Super Admin already exists.

The fresh-installation path no longer requires a human-operated `/platform/bootstrap/claim`. The historical claim implementation remains disabled unless explicitly required for compatibility/migration.

## 5. Identity boundary after v1.4.4

Clerk owns:

- password/passkey;
- MFA;
- verification and recovery;
- human authentication sessions and Clerk JWTs.

Security owns:

- initial system administrator provisioning;
- global USER record and lifecycle;
- Clerk-to-Security USER mapping;
- Platform and Tenant authorization;
- Super Admin role assignment and authority data;
- Security access/session decisions.

Initial system provisioning does not authenticate the user. After provisioning, the selected Clerk account signs in normally and Security resolves the Clerk `sub` to the provisioned global USER.

## 6. Current execution direction

```text
feature/super-admin-system-provisioning-v1.4.4
       ↓
Security CI + Neon regression
       ↓
PR -> dev with controlled provisioning marker
       ↓
exact-commit Security CI
       ↓
one-time DEV initial Super Admin data provisioning
       ↓
verify ACTIVE mapping + full permission coverage
       ↓
Railway DEV exact-digest proof
       ↓
normal Clerk authentication / Security Platform Admin login proof
       ↓
resume Increment G
```

## 7. Other deferred work

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
