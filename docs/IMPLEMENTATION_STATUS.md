# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4 + Phase 1 Self-Onboarding/Clerk Integration v1.4.5  
**Last updated:** 2026-08-14

Detailed execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Current promoted runtime baseline

```text
7765e72a6078a15981cffb42c0d7e3bdbdc269de
```

The DEV runtime includes global one-time USER identity, Security-owned lifecycle, Phase 1 self-onboarding through Clerk Backend user creation, Tenant authorization without Tenant-membership dependency, built-in full-authority `platform.super_admin`, controlled initial administrator provisioning, and immutable exact-digest Railway deployment.

## 2. Phase 1 normal USER onboarding v1.4.5 — DONE / DEPLOYED

Normal human USER onboarding is Platform-global and one-time. v1.4.5 supersedes the invitation/bind registration sequence from v1.4.2.

```text
one self-registration request to Security
  -> validate global onboarding key
  -> validate globally unique email + normalized Indian mobile
  -> Security calls Clerk Backend POST /v1/users
  -> Clerk returns immutable user_...
  -> Security persists USER=PENDING + CLERK mapping + PENDING_ADMIN_APPROVAL
  -> Security Admin/Super Admin later activates USER
```

Frozen Phase 1 identity choices:

```text
Sign-in identifier = email address
Separate username  = none
Indian mobile      = Verigence-only; not sent to Clerk
Clerk phone        = none; no dummy US number
MFA                = deferred to Phase 2
Tenant data        = not part of onboarding
```

The registration API accepts first name, last name, email, mobile and password plus `X-Onboarding-Key`. Password is transient only: TLS transport, immediately forwarded to Clerk, and never stored/hashed/logged/audited by Security.

Clerk Backend user creation receives only first name, last name, email and password. The active `/onboarding/users/{requestId}/bind` endpoint and Clerk invitation creation are retired from Phase 1.

If Clerk creation succeeds but Security persistence fails, Security attempts compensating Clerk user deletion. Security remains fail-closed if compensation itself fails because no usable local USER mapping is committed.

## 3. v1.4.5 evidence

```text
Feature head:             fd72e24d833ad28c129cff185656719b699177c8
Feature Security CI:      31779990307 — PASS
Feature Neon/PostgreSQL:  31779986825 — PASS
PR #54:                   MERGED
Promoted DEV commit:      7765e72a6078a15981cffb42c0d7e3bdbdc269de
Post-merge Security CI:   31780116228 — PASS
Railway DEV:              31780116188 — PASS
readiness/liveness/correlation: PASS
```

Detailed report:

```text
docs/PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_TEST_REPORT_v1.4.5.md
```

## 4. Identity and authorization ownership

Clerk owns human credentials and authentication sessions. Phase 1 does not require MFA.

Security owns global USER status, email/mobile uniqueness and profile data, Clerk-to-Security mapping, Platform/Tenant authorization, device/access controls, Security access tokens, and administrator activation/deactivation decisions.

Tenant membership is not a human access prerequisite. An ACTIVE USER can receive different authorization in multiple Tenants without another onboarding event.

## 5. Initial Super Admin v1.4.4 — DONE / PROVISIONED / DEPLOYED

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
```

Verified state: principal ACTIVE, global USER ACTIVE, CLERK mapping ACTIVE, Super Admin ACTIVE and zero missing ACTIVE Security permissions.

## 6. Current execution direction

```text
Phase 1 self-onboarding v1.4.5  DONE / DEPLOYED
       ↓
Increment G maker-checker       NEXT
```

## 7. Deferred work

Still unresolved unless a later tracker says otherwise:

- MFA / step-up authentication — Phase 2;
- complete SEC-032 Tenant activation prerequisite catalogue;
- persistent cross-replica idempotency store;
- device `BLOCKED` vs `REVOKED` business semantics;
- broader Clerk webhook lifecycle semantics;
- SYSTEM/SERVICE_INTEGRATION issuance;
- retention/offboarding execution;
- overlapping JWKS rotation;
- WPM catalogue;
- UAT/Production readiness.
