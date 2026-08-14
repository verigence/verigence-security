# Verigence Security — Clerk-Owned Email OTP Onboarding Design v1.4.6

**Status:** APPROVED IMPLEMENTATION AMENDMENT  
**Date:** 2026-08-14  
**Repository:** `verigence/verigence-security`  
**Supersedes:** The backend `POST /v1/users` creation and implicit-email-verification portions of `SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md`.  
**Preserves:** Global one-time onboarding, email as sign-in ID, Indian mobile stored only in Verigence, no Tenant membership requirement, no MFA in Phase 1, Security-owned USER lifecycle, and Security Admin approval.

## 1. Frozen responsibility split

### Verigence Security owns
- the Platform onboarding key;
- first name, last name and Indian mobile capture/validation;
- global duplicate checks for email and normalized mobile;
- a short-lived signup authorization attempt;
- validation of the completed Clerk session JWT;
- confirmation that the Clerk email equals the pre-authorized email and is verified;
- creation of the global Security USER as `PENDING`;
- Security Admin / Super Admin approval and all authorization.

### Clerk owns
- password collection and password policy;
- credential storage;
- email OTP generation and delivery;
- email OTP validation;
- creation of the Clerk `user_...` identity and session;
- later interactive authentication.

Verigence MUST NOT receive, proxy, store, hash, log, audit, or validate a signup password in v1.4.6.

## 2. User experience

The UI may present one Sign Up form containing:

```text
Onboarding Key
First Name
Last Name
Email
Indian Mobile
Password
Confirm Password
```

One click on **Sign Up** may perform multiple calls behind the UI. The user does not need to understand those calls.

## 3. Authoritative Phase 1 sequence

```text
User clicks Sign Up
  -> UI sends onboarding key + first name + last name + email + mobile to Verigence
  -> Verigence validates onboarding key, fields, duplicate email and duplicate mobile
  -> Verigence creates a short-lived AUTHORIZED_FOR_CLERK signup attempt
  -> Verigence returns signupAttemptId
  -> UI sends email + password directly to Clerk SDK
  -> Clerk starts sign-up and sends email verification OTP
  -> User enters OTP
  -> UI sends OTP directly to Clerk
  -> Clerk verifies OTP, completes sign-up and establishes Clerk session
  -> UI calls Verigence completion endpoint with signupAttemptId + Clerk session JWT
  -> Verigence verifies JWT signature/issuer/authorized party
  -> Verigence reads immutable Clerk `sub=user_...`
  -> Verigence GETs Clerk User and requires the pre-authorized email to be present and verification.status=verified
  -> Verigence optionally synchronizes first/last name to Clerk
  -> Verigence transaction creates:
       security_principals = ACTIVE
       security.users = PENDING
       external_identities = CLERK / user_... / ACTIVE
       platform_user_onboarding_requests = PENDING_ADMIN_APPROVAL
       security event/audit evidence
  -> Verigence marks signup attempt COMPLETED
  -> response: registration successful, pending administrator approval
```

No Security USER exists before successful Clerk email verification.

## 4. Verigence API contract

### 4.1 Start / pre-authorize signup

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <Platform onboarding key>
```

Request body:

```json
{
  "firstName": "Amit",
  "lastName": "Goyal",
  "email": "amit@example.com",
  "mobile": "+919876543210"
}
```

There is intentionally **no password field** in the Security API.

Success response: HTTP 202

```json
{
  "signupAttemptId": "<uuid>",
  "status": "CLERK_EMAIL_VERIFICATION_REQUIRED",
  "expiresAt": "<UTC timestamp>"
}
```

The signup attempt expires after 30 minutes.

### 4.2 Complete verified signup

```text
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
```

Success response: HTTP 201

```json
{
  "onboardingRequestId": "<uuid>",
  "status": "PENDING_ADMIN_APPROVAL",
  "message": "Registration successful. Pending administrator approval."
}
```

## 5. Clerk frontend integration contract

For supported Clerk Core 3 React/Next/Expo SDKs, the custom flow is:

```text
signUp.password({ emailAddress, password })
signUp.verifications.sendEmailCode()
signUp.verifications.verifyEmailCode({ code })
signUp.finalize(...)
```

Clerk must be configured with:
- Sign-up with email enabled;
- Require email address enabled;
- Verify at sign-up = Email verification code;
- Sign in with email enabled;
- Sign-up with password enabled;
- MFA not required for Phase 1.

The password and OTP are sent only between the client and Clerk.

## 6. Clerk backend verification contract

After the client presents the Clerk session JWT, Security:
1. validates the JWT using the configured Clerk issuer/JWT key and authorized parties;
2. uses JWT `sub` as the immutable Clerk User ID;
3. calls `GET /v1/users/{user_id}` using backend-only `CLERK_SECRET_KEY`;
4. finds the pre-authorized email in `email_addresses`;
5. requires its `verification.status` to equal `verified`;
6. rejects if the email differs, is absent, or is not verified.

Security may call `PATCH /v1/users/{user_id}` to synchronize first and last name after verification. No phone number, username, Tenant, role or permission is sent to Clerk.

## 7. Identity and duplicate rules

- Email is the Phase 1 sign-in ID and is globally unique case-insensitively in Security.
- Indian mobile is Verigence-only and globally unique after normalization to `+91XXXXXXXXXX`.
- `signup_attempt_id` is a temporary workflow identifier, not a USER identifier.
- Verigence `user_id` is generated only during successful completion.
- Clerk `user_...` is accepted only from a verified Clerk session.

Only one live signup attempt may exist for a given normalized email or mobile. Expired attempts do not block a new registration.

## 8. Failure rules

- Invalid/disabled onboarding key: reject before Clerk signup begins.
- Duplicate Security email/mobile: reject before Clerk signup begins.
- Expired signup attempt: reject completion; user restarts signup.
- Invalid Clerk session JWT: reject completion.
- Clerk email mismatch or unverified email: reject completion and create no Security USER.
- Duplicate race at completion: reject; create no duplicate Security USER.
- Clerk identity already linked to another Security USER: reject.
- Security persistence failure: create no usable Security USER; the Clerk account may exist but has no Verigence access until a valid completion succeeds or an operator reconciles it.

Unlike v1.4.5, Security does not delete the Clerk user as automatic compensation for a completion database failure because Clerk account creation is now a user-owned, verified identity event rather than a backend provisioning side effect.

## 9. Phase 1 vs Phase 2

Email OTP at signup is **email ownership verification**, not Verigence MFA.

Phase 1:
- email + password;
- email OTP verification at signup;
- Security USER lifecycle/RBAC/device controls;
- MFA not required.

Phase 2 may add TOTP/authenticator, backup codes, passkeys, privileged-operation step-up or other MFA without changing the global USER identity model.

## 10. Acceptance criteria

Automated evidence must prove:
1. invalid onboarding key creates no signup attempt;
2. duplicate email/mobile creates no signup attempt;
3. start endpoint accepts no password field and returns a 30-minute attempt;
4. completion requires a valid Clerk session identity;
5. Clerk email must exactly match the pre-authorized normalized email;
6. Clerk email verification status must be `verified`;
7. no Security USER exists before successful completion;
8. successful completion creates one `PENDING` Security USER, one CLERK mapping and one `PENDING_ADMIN_APPROVAL` request;
9. mobile is never sent to Clerk;
10. first/last name synchronization does not alter email verification state;
11. expired or already-completed attempts cannot be reused;
12. active `/bind` and backend-create-user onboarding paths remain absent;
13. historical Tenant authorization and Super Admin regressions remain green;
14. live E2E proves Clerk sends/validates OTP before Security creates the PENDING USER.

## 11. Final invariant

> **Verigence decides whether a person is allowed to begin signup; Clerk owns password and email OTP verification; only a successfully verified Clerk identity can be finalized into a PENDING Verigence USER.**
