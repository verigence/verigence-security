# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current authentication authority:** `SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md`  
**Status:** IMPLEMENTED / PROMOTED TO DEV / RUNTIME HEALTHY  
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

v1.4.8 is merged into `dev` and is the active DEV implementation baseline.

Implemented and promoted:

- additive migration for Clerk email-address correlation ID;
- backend-only Clerk user creation, forced-unverified email and email-code preparation;
- backend OTP attempt verification;
- backend password/TOTP credential verification;
- backend normal USER login;
- backend Platform Admin login and initial Super Admin claim;
- existing administrator activation continues to unban the Clerk user before activating Security USER;
- v1.4.1/v1.4.6 client-Clerk contracts explicitly marked historical/superseded;
- route-contract checks prevent the retired `/complete` route from silently returning;
- Railway/Neon runtime PostgreSQL URLs are normalized to the installed psycopg v3 driver;
- Railway deployment uses the validated scoped Project Token for immutable-image source updates.

## 6. Validation evidence

Completed successfully:

```text
Python compile                         PASS
CI static/design integrity checks      PASS
Ruff                                   PASS
Mypy                                   PASS
v1.4.8 route-contract validation       PASS
pytest                                 PASS
package build                           PASS
Neon/PostgreSQL migration validation   PASS
Railway immutable-image deployment     PASS
/health/ready                           PASS
/health/live                            PASS
X-Correlation-ID propagation           PASS
```

The live DEV runtime has also confirmed that the required Security runtime configuration is present without exposing
secret values.

### Provider E2E still intentionally pending

The following acceptance evidence requires a controlled real test mailbox/account and is **not falsely marked as
complete**:

```text
live Clerk email delivery -> user enters OTP -> Security PENDING approval E2E
live approved USER credential login -> Security JWT E2E using controlled test identity
```

The implementation, database and Railway runtime are promoted and healthy; the two provider-facing human-flow tests
remain a separate controlled E2E validation step.

## 7. Superseded documents

The following remain only for Git/history traceability and are not active architecture:

```text
SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md     where conflicting with v1.4.8
SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md
CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md
IMPLEMENTATION_PROGRESS_TRACKER_v1.4.6.md
IMPLEMENTATION_STATUS_v1.4.6.md
NEXT_STEPS_AND_CONTEXT_RECOVERY_v1.4.6.md
PHASE1_CLERK_EMAIL_OTP_TEST_PLAN_v1.4.6.md
```

## 8. Canonical design

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

Any future implementation or Web/Mobile integration must use that document as the authentication/onboarding source
of truth unless a later owner-approved version explicitly supersedes it.

## 9. Next platform step

Implement the Audit Core authentication/onboarding facade so the designed channel boundary is enforced end-to-end:

```text
Web / Mobile -> Audit Core -> Security -> Clerk Backend API
```

Audit Core must proxy only the required application contracts, redact transient secrets, and never acquire a Clerk
secret or Clerk session dependency.
