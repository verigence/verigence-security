# Verigence Security — Implementation Progress Tracker v1.4.6

**Status:** SUPERSEDED / HISTORICAL  
**Superseded:** 2026-08-17 by backend-only authentication and email OTP v1.4.8.

This tracker records historical work on the v1.4.6 client-to-Clerk experiment. It is not a current execution
source.

Current execution tracker:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER.md
```

Current authentication/onboarding design:

```text
docs/SECURITY_BACKEND_AUTH_AND_EMAIL_OTP_DESIGN_v1.4.8.md
```

Active boundary:

```text
Web / Mobile -> Audit Core -> Security -> Clerk Backend API
```

No new code may use the v1.4.6 Clerk SDK/session-JWT channel flow.
