# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4 + Clerk Email OTP Onboarding v1.4.6  
**Last updated:** 2026-08-14

Detailed execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Current promoted runtime baseline

```text
7765e72a6078a15981cffb42c0d7e3bdbdc269de
```

This is still the promoted v1.4.5 runtime until PR #56 is merged and exact-commit Railway promotion succeeds. v1.4.6 is currently validated on its feature branch but is not yet the promoted runtime.

## 2. Phase 1 Clerk-owned email OTP onboarding v1.4.6 — UNDER VALIDATION

v1.4.6 supersedes only the active backend Clerk `POST /v1/users` registration sequence from v1.4.5. The global once-per-person USER model, email sign-in ID, Verigence-only Indian mobile, Security-owned lifecycle and Tenant authorization rules are unchanged.

```text
user submits onboarding key + first name + last name + email + Indian mobile
  -> Security validates key + global email/mobile uniqueness
  -> Security creates short-lived signupAttemptId; no USER exists yet
  -> client sends email + password directly to Clerk
  -> Clerk sends and verifies email OTP
  -> Clerk finalizes authenticated session
  -> client sends signupAttemptId + Clerk session JWT to Security
  -> Security validates Clerk JWT + exact verified email
  -> Security creates global USER=PENDING + CLERK mapping + PENDING_ADMIN_APPROVAL
  -> Security Admin/Super Admin later activates USER
```

Frozen Phase 1 identity choices:

```text
Sign-in identifier = email address
Separate username  = none
Indian mobile      = Verigence-only; never sent to Clerk
Clerk phone        = none; no dummy US number
Password           = Clerk-only; never sent to Security in v1.4.6
Email OTP          = Clerk-owned email ownership verification
MFA                = deferred to Phase 2
Tenant data        = not part of identity onboarding
```

Active v1.4.6 API contract:

```text
POST /security/v1/onboarding/users
  -> HTTP 202 / CLERK_EMAIL_VERIFICATION_REQUIRED
  -> returns signupAttemptId + expiresAt

POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
  -> HTTP 201 / PENDING_ADMIN_APPROVAL after verified Clerk email
```

The active Security onboarding API no longer accepts a password. Clerk invitations and the historical `/bind` path remain retired.

## 3. v1.4.6 feature evidence so far

```text
Exact feature head:        e9cf8326b1e0a49b164dac028a218b2f016eb77d
Security CI #186:          PASS
Neon/PostgreSQL #171:      PASS
PR #56:                    OPEN / DRAFT / NOT YET MERGED
Railway DEV promotion:     PENDING MERGE
Live Clerk OTP E2E:        PENDING DEPLOYMENT
```

The real PostgreSQL acceptance proves no Security USER exists after pre-authorization or unverified-email completion, and a matching Clerk identity with `verification.status=verified` creates exactly one `PENDING` USER, ACTIVE CLERK mapping and `PENDING_ADMIN_APPROVAL` request. Existing global USER/cross-Tenant and Platform Super Admin regressions remain green.

Governing documents:

```text
docs/SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md
docs/CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md
docs/PHASE1_CLERK_EMAIL_OTP_TEST_PLAN_v1.4.6.md
```

## 4. v1.4.5 — HISTORICAL DEPLOYED BASELINE / SUPERSEDED ONBOARDING CREATION PATH

v1.4.5 proved the original self-onboarding shape and remains valid historical evidence for global email/mobile uniqueness, Security `PENDING` lifecycle, no Tenant onboarding, no username, no Clerk phone and deployment discipline. Its backend `POST /v1/users` creation path is superseded because backend-created Clerk emails are treated as verified and therefore cannot provide the email-ownership OTP proof now required.

Historical report:

```text
docs/PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_TEST_REPORT_v1.4.5.md
```

## 5. Identity and authorization ownership

Clerk owns human passwords, email OTP verification, credentials and authentication sessions. Phase 1 does not require MFA.

Security owns the Platform onboarding key, global USER status, email/mobile uniqueness, Clerk-to-Security mapping, Platform/Tenant authorization, device/access controls, Security access tokens, and administrator activation/deactivation decisions.

Tenant membership is not a human access prerequisite. An ACTIVE USER can receive different authorization in multiple Tenants without another onboarding event.

## 6. Initial Super Admin v1.4.4 — DONE / PROVISIONED / DEPLOYED

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
```

Verified state: principal ACTIVE, global USER ACTIVE, CLERK mapping ACTIVE, Super Admin ACTIVE and zero missing ACTIVE Security permissions.

## 7. Current execution direction

```text
v1.4.6 Clerk email OTP onboarding   FEATURE GATES GREEN / MERGE NEXT
       ↓
Railway DEV + live Clerk OTP E2E
       ↓
Increment G maker-checker
```

## 8. Deferred work

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
