# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4  
**Last updated:** 2026-08-14

Detailed execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Current promoted runtime baseline

```text
951a7694b31c195ccbde45d13346e0eea8ae9f14
```

This DEV runtime includes global one-time USER onboarding, Security-owned USER lifecycle, Tenant authorization without Tenant-membership dependency, built-in full-authority `platform.super_admin`, controlled initial administrator provisioning, and immutable exact-digest Railway deployment.

## 2. Identity and onboarding model

Normal human USER onboarding is Platform-global and one-time. A USER is not onboarded again when authorization is added in another Tenant.

Clerk owns credentials, MFA, verification, recovery and human authentication sessions.

Security owns the global USER record/status, initial administrator setup, Clerk-to-Security mapping, Platform/Tenant authorization, devices/access controls and Security access tokens.

## 3. Initial Super Admin v1.4.4 — DONE / PROVISIONED / DEPLOYED

DEV selected Clerk identity:

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
```

Verified Security state:

```text
Principal               ACTIVE
Global USER             ACTIVE
CLERK external identity ACTIVE
platform.super_admin    ACTIVE
Missing ACTIVE permissions from Super Admin = 0
```

No Tenant membership, Tenant role or local password credential is required for this initial administrator.

Fresh installation no longer depends on a manual `/platform/bootstrap/claim`; the historical route remains compatibility code and is disabled by default.

## 4. v1.4.4 evidence

```text
PR #51 feature CI:       31775948471 — PASS
PR #51 feature Neon:     31775946314 — PASS
PR #51:                  MERGED
First provisioning:      31776049219 — FAIL / TRANSACTION ROLLED BACK
PR #52 hotfix CI:        31776200341 — PASS
PR #52 hotfix Neon:      31776189798 — PASS
PR #52:                  MERGED
Runtime commit:          951a7694b31c195ccbde45d13346e0eea8ae9f14
Post-merge Security CI:  31776274556 — PASS
Initial provisioning:    31776274559 — PASS
Railway DEV:             31776274539 — PASS
readiness/liveness/correlation: PASS
```

Detailed report: `docs/INITIAL_SUPER_ADMIN_PROVISIONING_TEST_REPORT_v1.4.4.md`.

## 5. Current execution direction

The Security-side initial administrator dependency is closed.

Next:

```text
separate UI/auth client performs normal Clerk login
       ↓
Clerk session JWT
       ↓
Security Platform Admin token exchange + /platform/me
       ↓
full effective authority proof
       ↓
Increment G maker-checker
```

No Clerk password, secret key or long-lived session token should be committed to Git for this proof.

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
