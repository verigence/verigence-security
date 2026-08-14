# Verigence Security — Implementation Status v1.4.6

**Status:** UNDER VALIDATION  
**Current focus:** Clerk-owned email OTP onboarding.

The active Phase 1 model is now:

```text
Security onboarding-key + duplicate precheck
  -> short-lived signup attempt
  -> client-to-Clerk email/password signup
  -> Clerk email OTP
  -> Clerk verified session JWT
  -> Security completion
  -> global USER=PENDING
  -> Security Admin approval
```

The v1.4.5 backend Clerk `POST /v1/users` flow is superseded for active onboarding because backend-created email addresses are automatically treated as verified by Clerk. Password is no longer part of the active Security onboarding API.

Validation is pending exact-head Security CI, Neon/PostgreSQL, merge, Railway DEV promotion, and one live Clerk OTP E2E with manual Clerk inspection before cleanup.
