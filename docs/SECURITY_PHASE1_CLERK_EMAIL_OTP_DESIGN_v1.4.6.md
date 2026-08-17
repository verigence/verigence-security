# Verigence Security — Clerk-Owned Email OTP Onboarding Design v1.4.6

**Status:** SUPERSEDED / HISTORICAL  
**Original date:** 2026-08-14  
**Superseded:** 2026-08-17 by `SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md`

This document is retained only as historical traceability for the short-lived client-to-Clerk v1.4.6 design.

The following v1.4.6 assumptions are **not active architecture**:

```text
Web/Mobile -> Clerk SDK
client submits password directly to Clerk
client submits email OTP directly to Clerk
client receives Clerk session JWT
client calls Security /complete with Clerk session JWT
```

The active contract is v1.4.8:

```text
Web/Mobile -> Audit Core -> Security -> Clerk Backend API
```

Password and OTP are entered in the Verigence UI but are transient request secrets only. Security talks to Clerk
server-to-server. No Web/Mobile Clerk SDK, key or session is permitted.

Current authoritative design:

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

Git history retains the original v1.4.6 content for audit/traceability.
