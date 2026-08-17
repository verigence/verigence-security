# Verigence Security — Clerk Email OTP Integration Contract v1.4.6

**Status:** SUPERSEDED / HISTORICAL  
**Original date:** 2026-08-14  
**Superseded:** 2026-08-17 by `SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md`

The v1.4.6 contract used a Clerk client SDK and a Clerk session JWT in the channel. That is no longer an approved
Verigence integration path.

## Active contract

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

The user enters password and email OTP in the Verigence UI. Audit Core passes the transient values to Security;
Security is the only Verigence component that calls Clerk. Password and OTP are never persisted, hashed, logged,
audited or returned.

Active Security signup routes:

```text
POST /security/v1/onboarding/users
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
```

The old route below is retired:

```text
POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
```

Normal active credential authentication is:

```text
POST /security/v1/auth/login
POST /security/v1/platform/auth/login
POST /security/v1/platform/bootstrap/claim
```

All Clerk operations are server-to-server from Security.

Current authoritative design and integration contract:

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

Git history retains the original v1.4.6 contract for traceability.
