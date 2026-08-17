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

## Current implementation baseline

```text
Branch: dev
Status: IMPLEMENTED / PROMOTED / RUNTIME HEALTHY
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

## Completed validation

```text
1. Security CI                              PASS
2. static/design integrity                  PASS
3. compile + Ruff + Mypy                     PASS
4. v1.4.8 route-contract gate               PASS
5. pytest                                    PASS
6. package build                             PASS
7. PostgreSQL/Neon migration validation      PASS
8. Railway immutable-image promotion         PASS
9. Railway readiness                         PASS
10. Railway liveness                         PASS
11. correlation-ID propagation               PASS
```

## Controlled provider E2E pending

These require a controlled mailbox/test identity and remain intentionally open:

```text
live Clerk email delivery -> OTP -> Security PENDING approval
live approved USER credential login -> Security JWT
```

This does not change the active DEV design/implementation status; it is provider-facing acceptance evidence still to
be collected before production/UAT sign-off.

## Preserved architecture

- Security remains the identity, authorization and access-policy authority.
- Clerk remains the human credential store/verifier only.
- Global USER and administrator approval semantics are unchanged.
- Tenant RBAC remains Security-owned.
- DI authorization/system integration work already completed is not changed by this increment.
- No DI repository change is part of v1.4.8.

## Historical documents

The v1.4.1/v1.4.6 client-Clerk documents are explicitly superseded where conflicting. Git history retains them for
traceability, but they are not implementation sources.

## Next implementation workstream

```text
Audit Core authentication/onboarding facade
        ↓
Web / Mobile -> Audit Core -> Security -> Clerk Backend API
```

The channel must never call Security or Clerk directly once the Audit Core facade is implemented.
