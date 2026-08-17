# Verigence Security — Phase 1 Clerk Email OTP Test Plan v1.4.6

**Status:** SUPERSEDED / HISTORICAL  
**Superseded:** 2026-08-17 by v1.4.8 backend-only authentication/email OTP validation.

The original v1.4.6 test plan validated a client-Clerk SDK/session-JWT flow and must not be used for new acceptance.

The v1.4.8 acceptance gates are defined in:

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

The active test boundary is:

```text
Web / Mobile -> Audit Core -> Security -> Clerk Backend API
```

Security tests must prove server-side banned-user creation, explicit email unverify, email-code preparation and
attempt verification, no password/OTP persistence, PENDING administrator approval, backend credential login, and
Security JWT issuance.
