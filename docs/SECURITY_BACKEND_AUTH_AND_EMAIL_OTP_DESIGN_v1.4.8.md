# Verigence Security — Backend Authentication and Email OTP Design v1.4.8

**Status:** APPROVED IMPLEMENTATION CORRECTION  
**Date:** 2026-08-17  
**Repository:** `verigence/verigence-security`  
**Supersedes where conflicting:** `SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`, `SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md`, and `CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md`.  
**Carries forward:** the backend-only Clerk facade principle from `SECURITY_CLERK_BACKEND_FACADE_DESIGN_v1.4.2.md`, plus the global USER/onboarding and administrator-approval model already implemented on `dev`.

## 1. Governing boundary

The Verigence application channel has one external application boundary:

```text
Web / Mobile
     |
     v
Audit Core
     |
     v
Security
     |
     v
Clerk Backend API
```

For identity/authentication, Audit Core is a channel facade and Security is the identity/authentication authority.
Audit Core MUST NOT hold `CLERK_SECRET_KEY` or call Clerk directly.

### AUTH-BOUNDARY-001

Web/Mobile MUST NOT:

- call Clerk Frontend or Backend APIs;
- include a Clerk SDK;
- contain Clerk publishable/secret keys;
- receive or persist a Clerk session token;
- use Clerk Organizations/RBAC as Verigence authorization.

### AUTH-BOUNDARY-002

Security alone owns the Clerk backend integration. `CLERK_SECRET_KEY` is a Security deployment secret.

### AUTH-BOUNDARY-003

Clerk owns human credential storage and credential verification. Security owns Verigence USER lifecycle,
authorization, Tenant governance, access policy, access sessions and Verigence JWT issuance.

## 2. Secret-handling invariant

Password, email OTP and future TOTP values are transient request secrets.

They may travel only over TLS on the active request path:

```text
Web/Mobile -> Audit Core -> Security -> Clerk
```

Neither Audit Core nor Security may persist, hash, audit, trace, cache or log those values. They must not appear in
exception detail, structured logs, correlation metadata or database snapshots.

Security API request models use secret/redacted field types where supported. Audit Core must apply equivalent
redaction when its channel facade is implemented.

## 3. Why backend email verification needs an explicit correction

Clerk Backend `createUser()` automatically marks email addresses supplied during user creation as verified. That
provider behavior cannot by itself prove that the human controls the email address.

The approved workaround is:

1. create the Clerk user already **banned**;
2. obtain the created email-address ID;
3. immediately update that email address to `verified=false`;
4. call the Clerk email-address `prepare_verification` Backend API with `strategy=email_code`;
5. accept the OTP only through Verigence;
6. call Clerk `attempt_verification` server-to-server;
7. independently re-read the Clerk user and require the exact signup email to be verified;
8. keep the Clerk user banned until Security administrator approval activates the Verigence USER.

The initial `banned=true` state is mandatory because it prevents the transient provider-created verified state from
creating a usable sign-in path before the email is explicitly verified and the Verigence administrator approves the
USER.

## 4. Self-signup sequence

```text
User enters:
  onboarding key
  first name
  last name
  email
  Indian mobile
  password
        |
        v
Web/Mobile -> Audit Core -> Security
        |
        +-- validate onboarding key
        +-- normalize/validate email and Indian mobile
        +-- reject existing Security email/mobile
        +-- reject another live signup attempt
        |
        v
Security creates signupAttemptId = AUTHORIZED_FOR_CLERK
        |
        v
Security -> Clerk Backend API
        |
        +-- create user with email/password/name and banned=true
        +-- PATCH created email verified=false
        +-- prepare_verification(strategy=email_code)
        |
        v
Clerk sends OTP to the signup email
        |
        v
User enters OTP in Verigence UI
        |
        v
Web/Mobile -> Audit Core -> Security
        |
        v
Security -> Clerk attempt_verification(code)
        |
        +-- require exact signup email verification=verified
        |
        v
Security transaction creates:
  security_principals = ACTIVE
  security.users = PENDING
  external_identities = CLERK / ACTIVE
  platform_user_onboarding_requests = PENDING_ADMIN_APPROVAL
  security event = PENDING_ADMIN_APPROVAL
        |
        v
Clerk user remains BANNED
        |
        v
Security Admin / Platform Super Admin approves + assigns Tenant role
        |
        v
Security activates USER and unbans Clerk user
```

No Security USER is created before successful email ownership verification.

## 5. Security onboarding API contract

These are Security-internal platform contracts. Web/Mobile consume equivalent Audit Core facade routes once that
facade is implemented.

### 5.1 Start signup

```http
POST /security/v1/onboarding/users
X-Onboarding-Key: <key>
Content-Type: application/json
```

```json
{
  "firstName": "Amit",
  "lastName": "Goyal",
  "email": "amit@example.com",
  "mobile": "+919876543210",
  "password": "<transient secret>"
}
```

Success: HTTP 202

```json
{
  "signupAttemptId": "<uuid>",
  "status": "EMAIL_VERIFICATION_REQUIRED",
  "expiresAt": "<UTC timestamp>"
}
```

Security stores the signup profile, attempt ID and Clerk resource IDs. It does not store the password.

### 5.2 Verify email code

```http
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
Content-Type: application/json
```

```json
{
  "code": "<transient OTP>"
}
```

Success: HTTP 201

```json
{
  "onboardingRequestId": "<uuid>",
  "status": "PENDING_ADMIN_APPROVAL",
  "message": "Registration successful. Pending administrator approval."
}
```

Security stores no OTP.

### 5.3 Resend email code

```http
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
```

This requests another Clerk email-code verification challenge for the same live signup attempt. The signup attempt
expiry remains authoritative.

### 5.4 Retired signup completion contract

The v1.4.6 route below is retired from the active contract:

```text
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
```

No channel flow may depend on a Clerk session JWT after v1.4.8.

## 6. Normal USER authentication

The active application login sequence is backend-only:

```text
Web/Mobile
  -> Audit Core
  -> Security POST /security/v1/auth/login
       identifier + password + optional TOTP
       Tenant + device + geo context
  -> Security looks up exact Clerk user
  -> Security rejects unknown/banned/locked identity
  -> Security calls Clerk verify_password
  -> if Clerk TOTP is enabled, Security calls verify_totp
  -> Security resolves Clerk user ID -> Security USER
  -> Security applies USER/Tenant/RBAC/device/geo/schedule/network controls
  -> Security creates/reuses access_session
  -> Security issues Verigence Security JWT
  -> Audit Core returns the application session result to the channel
```

A Clerk credential-verification success is identity proof only. It never bypasses Security authorization.

The legacy `/security/v1/access-sessions` identity-token bridge remains temporarily available only for migration and
automated-test compatibility and is marked deprecated. It is not part of the Web/Mobile channel contract and must
not be used by the new Audit Core facade.

## 7. Platform Super Admin / Platform Admin authentication

Bootstrap and Platform Admin login use the same backend credential verifier.

```text
POST /security/v1/platform/bootstrap/claim
POST /security/v1/platform/auth/login
```

Both accept Verigence credential requests. Security verifies the credential through Clerk Backend API, constructs
an internal CLERK identity, then reuses the existing `PlatformIdentityService` authorization/token logic.

First Super Admin bootstrap additionally requires the authenticated immutable Clerk user ID to equal
`SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID` and preserves the single-active-bootstrap invariant.

No Clerk session JWT is required by these active routes.

## 8. Administrator approval remains authoritative

Successful email OTP verification does not activate application access.

```text
Email verified
   -> Security USER=PENDING
   -> onboarding=PENDING_ADMIN_APPROVAL
   -> Clerk user remains BANNED
```

The existing administrator lifecycle remains authoritative. When an administrator changes the Security USER to
`ACTIVE`, Security first unbans the linked Clerk user and only then commits the Security activation. If Clerk cannot
be enabled, activation fails closed.

Tenant role assignment remains a separate Security authorization action. The applicant never selects or activates
its own PC/TL/PM/CRM/administrator role.

## 9. Failure and recovery rules

1. Invalid/disabled onboarding key: reject before Clerk user creation.
2. Duplicate Security email/mobile: reject before Clerk user creation.
3. Clerk create/verification outage: return dependency-unavailable; never fall back to local credential handling.
4. Clerk rejects password/user creation: return a safe validation/authentication failure without provider payload.
5. OTP invalid/expired: create no Security USER.
6. Clerk email mismatch/unverified after OTP attempt: create no Security USER.
7. DB failure before Clerk user ID is stored: best-effort delete the banned Clerk user and cancel the signup attempt.
8. Expired abandoned signup: mark attempt expired and reconcile/delete its banned Clerk identity before allowing a
   replacement signup for the same identity.
9. Duplicate/racing verification: database locking and uniqueness rules allow at most one Security USER/mapping.
10. If OTP was already accepted by Clerk but Security persistence failed, retry may recognize the already-verified
    exact Clerk email and continue idempotently rather than requiring a second ownership proof.
11. Security USER activation failure to unban Clerk: fail closed; USER does not become ACTIVE.
12. No error response reveals password, OTP, Clerk secret key or raw Clerk provider payload.

## 10. Data persisted by Security

Allowed signup/runtime persistence includes:

```text
signupAttemptId
first/last name
normalized email
normalized Indian mobile
signup status/timestamps
Clerk user ID
Clerk email-address ID
Security USER/principal IDs
onboardingRequestId
Tenant authorization state
Security access-session state
```

Forbidden persistence includes:

```text
password
email OTP
TOTP code
Clerk secret key
Clerk client/session token
```

## 11. Clerk resource contract used

The approved implementation uses these Clerk Backend API capabilities only:

```text
POST  /users
PATCH /email_addresses/{email_address_id}
POST  /email_addresses/{email_address_id}/prepare_verification
POST  /email_addresses/{email_address_id}/attempt_verification
GET   /users
GET   /users/{user_id}
POST  /users/{user_id}/verify_password
POST  /users/{user_id}/verify_totp              when applicable
POST  /users/{user_id}/ban
POST  /users/{user_id}/unban
DELETE /users/{user_id}                         compensation/reconciliation only
```

Clerk Organizations/RBAC is not used.

## 12. Deployment configuration

Security backend requires:

```text
CLERK_SECRET_KEY
CLERK_BACKEND_API_URL=https://api.clerk.com/v1
```

Production/UAT active backend authentication does not require a Clerk publishable key in any channel application.
Legacy Clerk issuer/JWT verification settings may remain temporarily for the deprecated identity-token bridge but
are not part of the active v1.4.8 channel design.

## 13. Acceptance criteria

The implementation is acceptable only when automated evidence proves:

1. Web/Mobile Clerk dependency is zero in the active channel contract.
2. Start signup creates a Clerk user as banned.
3. Created email is explicitly reset to unverified before OTP preparation.
4. `email_code` verification is prepared server-to-server.
5. OTP is submitted to Security and verified server-to-server.
6. Password and OTP have no Security persistence columns or audit payloads.
7. No Security USER exists before successful email verification.
8. Successful verification creates exactly one PENDING USER and PENDING_ADMIN_APPROVAL request.
9. Clerk user remains banned while Security USER is PENDING.
10. Existing administrator activation unbans Clerk before activating Security USER.
11. Normal USER login verifies password through Clerk Backend API and issues only a Verigence Security JWT.
12. Platform bootstrap/login verifies credentials through Clerk Backend API and issues only Verigence tokens.
13. The old signup `/complete` Clerk-JWT route is absent from the active route contract.
14. The old identity-token access-session bridge is marked deprecated and is not used by the Audit Core channel.
15. Security CI, PostgreSQL migration validation and live DEV integration pass on the exact implementation commit.

## 14. Final invariant

> **The user experiences Verigence only. Clerk stores and verifies human credentials behind Security. Security owns
> identity lifecycle and authorization. Audit Core is the application-facing channel facade and never owns a Clerk
> secret or Clerk session.**
