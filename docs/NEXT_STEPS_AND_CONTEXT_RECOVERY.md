# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Current onboarding authority:** Clerk Email OTP Onboarding v1.4.6  
**Last updated:** 2026-08-14

## 1. Governing recovery rule

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md`;
3. `docs/CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md`;
4. `docs/PHASE1_CLERK_EMAIL_OTP_TEST_PLAN_v1.4.6.md`;
5. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`;
6. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`;
7. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for unchanged global lifecycle/Tenant authorization rules;
8. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
9. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`;
10. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
11. `docs/IMPLEMENTATION_STATUS.md`;
12. current `dev`, open Security PRs and CI/Railway state.

The v1.4.5 test report remains historical deployment evidence but its backend Clerk user-creation path is not the active onboarding authority.

## 2. Invariants that must survive every reset

```text
Normal human onboarding  = Platform-global, once per person
Phase 1 registration     = self-onboarding with one Platform onboarding key
Sign-in identifier       = email; no separate username
Indian mobile            = Verigence-only; never sent to Clerk in Phase 1
Password                 = Clerk-only in active v1.4.6 flow
Email OTP                = generated/delivered/verified by Clerk
Security USER creation   = only after matching Clerk email is verified
MFA                      = not Phase 1; introduce in Phase 2
Clerk                     = credential/authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Platform Super Admin      = built-in role with full Security authority
Initial administrator     = operator-selected Clerk user_... provisioned as setup data
```

Do not reconstruct Tenant-scoped identity onboarding, Clerk invitations, backend `POST /v1/users` as normal signup, Security-proxied passwords, the `/bind` flow, a dummy Clerk phone number, or a Phase 1 MFA requirement.

## 3. Active Phase 1 onboarding v1.4.6

The person receives the Platform onboarding key and fills the Verigence Sign Up UI with onboarding key, first name, last name, email, Indian mobile, password and confirm password. One button may orchestrate multiple calls; the user does not need to understand that split.

Authoritative backend/client order:

```text
UI -> Security start
   onboarding key + first/last name + email + mobile
   ↓
Security validates key + global email/mobile uniqueness
   ↓
Security creates 30-minute signupAttemptId
NO Security USER exists
   ↓
UI -> Clerk directly
   email + password
   ↓
Clerk sends email OTP
   ↓
UI -> Clerk directly
   OTP
   ↓
Clerk verifies email and finalizes session
   ↓
UI -> Security complete
   signupAttemptId + Clerk session JWT
   ↓
Security verifies JWT + exact Clerk email verification.status=verified
   ↓
Security creates:
   principal ACTIVE
   USER PENDING
   CLERK external identity ACTIVE
   onboarding request PENDING_ADMIN_APPROVAL
   ↓
Security Admin/Super Admin later changes PENDING -> ACTIVE
```

Password and OTP never transit the Security API.

## 4. Active Phase 1 API

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <Platform global key>
body: firstName, lastName, email, mobile
response: 202 + signupAttemptId + CLERK_EMAIL_VERIFICATION_REQUIRED
```

Then, after Clerk email OTP verification and session finalization:

```text
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
response: 201 + PENDING_ADMIN_APPROVAL
```

The deployed service must have the backend-only `CLERK_SECRET_KEY`, Clerk JWT verification configuration, and the normal Security database configuration. Secrets remain deployment-only.

## 5. Current validation state

At the latest recorded exact feature head:

```text
Head:                     e9cf8326b1e0a49b164dac028a218b2f016eb77d
Security CI #186:         PASS
Neon/PostgreSQL #171:     PASS
PR #56:                   OPEN / DRAFT
Merge/Railway:            PENDING
Live Clerk OTP E2E:       PENDING DEPLOYMENT
```

The live E2E must use a unique `gigsinopensource+verigence-e2e-<unique>@gmail.com` alias, prove the Clerk OTP, complete the Security PENDING record, and then **pause before deletion so the user can inspect the Clerk Dashboard record**. Cleanup happens only after explicit user confirmation.

## 6. Initial DEV Super Admin

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
Status:            ACTIVE
```

## 7. Tenant authorization rule

People are onboarded once as global Security USERs. The same `user_id` can receive independent roles, Groups, locations and schedules in multiple Tenants without another onboarding event or Tenant membership requirement.

## 8. Current workstream

```text
v1.4.6 Clerk email OTP onboarding
   ↓ merge + Railway + live E2E
Increment G maker-checker
   ↓
Increment H
   ↓
Increment I
   ↓
Increment J
```

## 9. Promotion discipline

```text
feature/*
   ↓ Security CI + applicable real Neon/PostgreSQL
  dev
   ↓ exact-commit Security CI
immutable GHCR image -> Railway DEV
   ↓ readiness + liveness + correlation
```
