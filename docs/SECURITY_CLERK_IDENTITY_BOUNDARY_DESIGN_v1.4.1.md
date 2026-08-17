# Verigence Security — Clerk Identity Boundary Design v1.4.1

**Status:** SUPERSEDED WHERE CONFLICTING / HISTORICAL AUTHENTICATION TRANSPORT  
**Original date:** 2026-08-13  
**Superseded for channel/authentication transport:** 2026-08-17 by `SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md`

This document originally established the separation between Clerk authentication and Verigence authorization. That
ownership separation remains valid, but its original **client -> Clerk -> Clerk session JWT -> Security** transport
is no longer approved.

## Preserved ownership decisions

The following v1.4.1 principles remain active:

```text
Clerk
  = human credential storage and credential verification

Security
  = Verigence USER identity/lifecycle
  = Platform and Tenant authorization
  = roles/groups/permissions
  = device/geo/schedule/network access policy
  = Verigence access sessions/JWTs
  = Security audit evidence

Clerk Organizations/RBAC
  = not a Verigence authorization source
```

A Clerk identity never grants Tenant access, role or permission by itself. Security remains the only Verigence
authorization authority.

## Superseded transport assumptions

The following historical v1.4.1 flow is retired:

```text
Web/Mobile -> Clerk SDK
Clerk session JWT -> Security
Security verifies Clerk session JWT as the active application login boundary
```

No new implementation may use that path.

## Active v1.4.8 boundary

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

Security holds the Clerk backend secret. Web/Mobile contain no Clerk SDK/key/session. Audit Core does not call Clerk
or hold a Clerk secret.

Password, email OTP and optional TOTP are transient request secrets only and must never be persisted, hashed,
logged, audited, traced or returned by Audit Core or Security.

The current authoritative authentication/onboarding design is:

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

Git history retains the complete original v1.4.1 design for historical traceability.
