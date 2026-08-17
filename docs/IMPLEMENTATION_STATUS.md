# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current implementation candidate:** `feat/signup-approval-v1`  
**Current authentication authority:** `SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md`  
**Last updated:** 2026-08-17

## 1. Canonical authentication boundary

```text
Web / Mobile
     -> Audit Core
     -> Security
     -> Clerk Backend API
```

Clerk is not a channel dependency. Web/Mobile must contain no Clerk SDK, key or session token. Audit Core does not
hold the Clerk secret and does not call Clerk directly. Security owns the Clerk backend integration.

Password, email OTP and optional TOTP values are transient request secrets only and are never stored, hashed,
logged, audited or returned by Security.

## 2. Active signup contract — v1.4.8

```text
POST /security/v1/onboarding/users
  onboarding key header
  first name + last name + email + Indian mobile + password
       |
       v
Security validates the Verigence onboarding gate
       |
       v
Security -> Clerk Backend
  create user BANNED
  force email verified=false
  prepare email_code verification
       |
       v
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
  user-entered OTP
       |
       v
Security -> Clerk attempt_verification
       |
       v
Security USER=PENDING
onboarding=PENDING_ADMIN_APPROVAL
Clerk user remains BANNED
       |
       v
Admin activation -> Security unbans Clerk -> USER ACTIVE
```

Resend route:

```text
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
```

The former v1.4.6 `/complete` + Clerk-session-JWT route is retired from the active route contract.

## 3. Active authentication contract

Normal USER:

```text
POST /security/v1/auth/login
  identifier + password + optional TOTP
  tenant + device + geo
       -> Clerk Backend credential verification
       -> Security authorization/access policy
       -> Verigence Security JWT
```

Platform administration:

```text
POST /security/v1/platform/auth/login
POST /security/v1/platform/bootstrap/claim
```

These also verify credentials through Clerk Backend API and return Verigence tokens only.

`POST /security/v1/access-sessions` remains deprecated migration/test compatibility only. It is not part of the new
Web/Mobile/Audit Core channel contract.

## 4. Preserved identity and authorization rules

- Human USER identity is Platform-global and one-time.
- Email is the Phase 1 sign-in identifier.
- Indian mobile remains Verigence-only and is not sent to Clerk.
- The applicant does not choose or activate a Tenant role.
- Email verification creates a PENDING Security USER, not an ACTIVE user.
- Platform Super Admin / Security Admin approval remains authoritative.
- Tenant roles/groups/permissions remain Security-owned.
- Clerk Organizations/RBAC remains unused as Verigence authority.
- Existing Security access-session, device, geo, schedule and network controls remain authoritative.

## 5. Current implementation state

The v1.4.8 changes are implemented on `feat/signup-approval-v1` and are **UNDER CI / INTEGRATION VALIDATION** until
all gates below pass and the exact commit is promoted.

Implemented on the feature branch:

- additive migration for Clerk email-address correlation ID;
- backend-only Clerk user creation, forced-unverified email and email-code preparation;
- backend OTP attempt verification;
- backend password/TOTP credential verification;
- backend normal USER login;
- backend Platform Admin login and initial Super Admin claim;
- existing administrator activation continues to unban the Clerk user before activating Security USER;
- v1.4.6 client-Clerk contracts explicitly marked historical/superseded;
- route-contract checks updated so the retired `/complete` route cannot silently return.

## 6. Validation gates before promotion

```text
Python compile
CI static/design integrity checks
Ruff
Mypy
route-contract validation
pytest
package build
Neon/PostgreSQL migration validation
Railway DEV deployment
live Clerk signup -> email OTP -> PENDING approval E2E
live approved USER credential login -> Security JWT E2E
```

Until these gates pass, v1.4.8 is an implementation candidate and not the promoted DEV baseline.

## 7. Superseded documents

The following remain only for Git/history traceability and are not active architecture:

```text
SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md
CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md
```

The v1.4.1 client-Clerk JWT model is also superseded wherever it conflicts with v1.4.8.

## 8. Canonical design

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

Any future implementation or Web/Mobile integration must use that document as the authentication/onboarding source
of truth unless a later owner-approved version explicitly supersedes it.
