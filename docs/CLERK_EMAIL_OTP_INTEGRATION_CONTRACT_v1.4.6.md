# Verigence Security — Clerk Email OTP Integration Contract v1.4.6

**Status:** IMPLEMENTATION CONTRACT  
**Date:** 2026-08-14

## Clerk Dashboard configuration required for Phase 1

- Sign-up with email: enabled.
- Require email address: enabled.
- Verify at sign-up: Email verification code.
- Sign in with email: enabled.
- Sign-up with password: enabled.
- MFA: not required in Phase 1.
- Phone number: not used by Verigence Phase 1 onboarding.
- Username: not used by Verigence Phase 1 onboarding.

## Client -> Verigence pre-authorization

```http
POST /security/v1/onboarding/users
X-Onboarding-Key: <key>
Content-Type: application/json

{
  "firstName": "Amit",
  "lastName": "Goyal",
  "email": "amit@example.com",
  "mobile": "+919876543210"
}
```

Security returns HTTP 202 with `signupAttemptId` only after key, data and duplicate validation succeed.

## Client -> Clerk Core 3 custom flow

For Clerk React/Next/Expo SDKs, the supported sequence is:

```text
signUp.password({ emailAddress, password })
signUp.verifications.sendEmailCode()
signUp.verifications.verifyEmailCode({ code })
signUp.finalize(...)
```

Password and OTP never transit Verigence Security.

## Client -> Verigence completion

After Clerk finalizes the verified signup session:

```http
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
```

Security validates the Clerk JWT, including signature, issuer, expiry and configured authorized party, and uses `sub` as the immutable Clerk `user_...` identity.

## Verigence -> Clerk backend verification

```http
GET https://api.clerk.com/v1/users/{user_id}
Authorization: Bearer <CLERK_SECRET_KEY>
```

Security locates the exact pre-authorized email in the returned `email_addresses` array and requires:

```json
{
  "email_address": "amit@example.com",
  "verification": {
    "status": "verified"
  }
}
```

A missing, different or unverified email fails closed and creates no Security USER.

After verification, Security may synchronize profile names only:

```http
PATCH https://api.clerk.com/v1/users/{user_id}

{
  "first_name": "Amit",
  "last_name": "Goyal"
}
```

Security does not send email, phone, username, password, Tenant, role or permission in this profile-sync call.

## Clerk backend lifecycle APIs retained

```text
GET    /v1/users/{user_id}        identity/profile verification
PATCH  /v1/users/{user_id}        first/last name synchronization
POST   /v1/users/{user_id}/ban    suspend/disable/exit enforcement
POST   /v1/users/{user_id}/unban  reactivation
DELETE /v1/users/{user_id}        controlled test/reconciliation cleanup only
```

The active v1.4.6 onboarding flow does not use:

```text
POST /v1/users
/v1/invitations
phone_number
username
Clerk Organizations / Clerk RBAC
MFA/TOTP/SMS
```

## Password rules

Password rules are owned entirely by Clerk and its Dashboard configuration. Verigence neither duplicates nor weakens Clerk password checks. The UI surfaces Clerk field errors returned by the Clerk SDK. Password reset/recovery also remains a Clerk function.

## Email OTP vs MFA

The email code in Phase 1 is proof of ownership of the sign-in email during account creation. It is not the Phase 2 MFA capability. Phase 2 may later require TOTP/authenticator/passkey/backup-code factors without changing this onboarding identity contract.
