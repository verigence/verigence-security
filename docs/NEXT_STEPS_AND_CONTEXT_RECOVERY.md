# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Current authentication/onboarding authority:** Backend Authentication and Email OTP v1.4.8  
**Last updated:** 2026-08-17

## 1. Governing recovery rule

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md`;
3. `docs/IMPLEMENTATION_STATUS.md`;
4. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`;
5. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`;
6. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`;
7. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for global USER/Tenant authorization rules;
8. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged control-plane rules;
9. current `dev`, open Security PRs and CI/Railway state.

The v1.4.1/v1.4.6 client-Clerk documents remain historical only where they conflict with v1.4.8.

## 2. Invariants that must survive every reset

```text
Application channel       = Web/Mobile -> Audit Core -> Security
Clerk integration         = Security -> Clerk Backend API only
Clerk SDK in Web/Mobile   = prohibited
Clerk session in channel  = prohibited
Normal human onboarding   = Platform-global, once per person
Phase 1 registration      = one Platform onboarding key
Sign-in identifier        = email; no separate username
Indian mobile             = Verigence-only; never sent to Clerk
Password                  = Clerk-owned; transient through Verigence only
Email OTP                 = Clerk-generated/delivered/verified via Security backend calls
Security USER creation    = only after exact Clerk email is verified
Applicant role choice     = prohibited
Admin approval            = required before USER becomes ACTIVE
MFA/TOTP                  = optional/future policy; Clerk verifies when enabled
Security                  = USER lifecycle + authorization/access-policy authority
Clerk                     = credential storage/verification only
```

Password, email OTP and TOTP values must never be persisted, hashed, logged, audited, traced or returned by
Audit Core or Security.

## 3. Active signup sequence

```text
User fills Verigence signup UI
  onboarding key + first/last name + email + Indian mobile + password
       ↓
Audit Core -> Security
       ↓
Security validates onboarding key + global email/mobile uniqueness
       ↓
Security creates short-lived signupAttemptId
       ↓
Security -> Clerk Backend
  create user banned=true
  force signup email verified=false
  prepare email_code verification
       ↓
Clerk sends OTP
       ↓
User enters OTP in Verigence UI
       ↓
Audit Core -> Security verify-email
       ↓
Security -> Clerk attempt_verification
       ↓
Security requires exact signup email verified
       ↓
Security creates:
  principal ACTIVE
  USER PENDING
  CLERK external identity ACTIVE
  onboarding request PENDING_ADMIN_APPROVAL
       ↓
Clerk user remains BANNED
       ↓
Security Admin/Super Admin later assigns approved Tenant role and activates USER
       ↓
Security unbans Clerk before USER activation commits
```

## 4. Active Security API

Security is a backend platform contract; Web/Mobile will consume Audit Core facade routes rather than call these
directly.

```text
POST /security/v1/onboarding/users
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
POST /security/v1/auth/login
POST /security/v1/platform/auth/login
POST /security/v1/platform/bootstrap/claim
```

Retired from active signup:

```text
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
```

Deprecated migration/test bridge only:

```text
POST /security/v1/access-sessions
```

## 5. Current implementation workstream

```text
feat/signup-approval-v1
   ↓
Security CI + static + Ruff + Mypy + pytest
   ↓
PostgreSQL migration validation
   ↓
Railway DEV
   ↓
live Clerk OTP onboarding E2E
   ↓
live approved-user credential login E2E
   ↓
Promote only after exact-commit evidence
```

## 6. Initial DEV Super Admin

The existing initial administrator remains the same Security/Clerk identity already provisioned in DEV. v1.4.8
changes how credentials reach Clerk; it does not create another bootstrap administrator.

## 7. Tenant authorization rule

People are onboarded once as global Security USERs. The same `user_id` can receive independent roles, Groups,
locations and schedules in multiple Tenants without another human identity-onboarding event.

## 8. Next platform dependency after Security is green

Implement the Audit Core authentication/onboarding facade so the channel boundary becomes real in runtime:

```text
Web / Mobile -> Audit Core -> Security -> Clerk Backend API
```

Audit Core must never receive or store `CLERK_SECRET_KEY`; it forwards transient credential/OTP requests to Security
with explicit secret redaction in logs/traces.

## 9. Historical warning

Do not resurrect:

```text
Web/Mobile -> Clerk SDK
Clerk publishable key in Web/Mobile
Clerk session JWT -> Security /complete
Clerk Organizations/RBAC as Verigence authority
applicant-selected roles
```
