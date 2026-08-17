# Verigence Security — Implementation Progress Tracker

**Status:** ACTIVE POINTER  
**Last updated:** 2026-08-17

## Current canonical authentication design

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

The active channel boundary is:

```text
Web / Mobile -> Audit Core -> Security -> Clerk Backend API
```

There is no approved Web/Mobile direct-Clerk path.

## Current implementation candidate

```text
Branch: feat/signup-approval-v1
Status: IMPLEMENTED / VALIDATION IN PROGRESS
Base:   Security dev
```

Implemented scope:

```text
signup start
  -> Security validates onboarding key/duplicates
  -> Clerk user created banned
  -> email explicitly reset unverified
  -> Clerk email OTP prepared

signup verify
  -> OTP submitted to Security
  -> Clerk Backend attempt_verification
  -> Security USER=PENDING
  -> PENDING_ADMIN_APPROVAL
  -> Clerk remains banned until administrator activation

normal login
  -> Security receives identifier/password/(optional TOTP)
  -> Clerk Backend verifies credentials
  -> Security applies Tenant/device/geo/access policy
  -> Verigence Security JWT

Platform Admin login/bootstrap
  -> same backend credential boundary
  -> existing Platform authorization/token service
```

No password, email OTP or TOTP value is persisted by Security.

## Route contract

Active:

```text
POST /security/v1/onboarding/users
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
POST /security/v1/auth/login
POST /security/v1/platform/auth/login
POST /security/v1/platform/bootstrap/claim
```

Retired from the active onboarding contract:

```text
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
```

Deprecated compatibility only:

```text
POST /security/v1/access-sessions
```

The deprecated bridge must not be used by the new Audit Core/Web/Mobile path.

## Validation sequence

```text
1. Security CI
2. static/design integrity
3. compile + Ruff + Mypy
4. route-contract gate
5. pytest
6. package build
7. PostgreSQL migration validation
8. Railway DEV promotion
9. live Clerk email OTP onboarding E2E
10. live credential login -> Security JWT E2E
```

Only after all relevant gates pass may this become the promoted `dev` authentication baseline.

## Preserved architecture

- Security remains the identity, authorization and access-policy authority.
- Clerk remains the human credential store/verifier only.
- Global USER and administrator approval semantics are unchanged.
- Tenant RBAC remains Security-owned.
- DI authorization/system integration work already completed is not changed by this increment.
- No DI repository change is part of v1.4.8.

## Historical documents

`SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md` and
`CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md` are explicitly marked superseded. Git history retains their
client-Clerk design for traceability, but it is not an implementation source.
