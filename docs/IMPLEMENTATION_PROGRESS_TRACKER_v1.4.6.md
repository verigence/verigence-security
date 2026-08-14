# Verigence Security — Implementation Progress Tracker v1.4.6

**Increment:** Phase 1 Clerk-owned email OTP self-onboarding  
**Status:** UNDER VALIDATION  
**Governing design:** `SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md`

## Scope

- Keep Platform-global self-onboarding key.
- Email remains the Phase 1 sign-in ID.
- Indian mobile remains Verigence-only and globally unique.
- Remove password from the Security onboarding API.
- Security pre-authorizes signup before Clerk is invoked by the UI.
- Clerk owns password, email OTP delivery, OTP verification and session creation.
- Security completes onboarding only after validating a Clerk session and verified matching email.
- Security USER is created only at completion and starts `PENDING`.
- MFA remains Phase 2.
- Tenant authorization remains separate from onboarding.

## Implementation checklist

- [x] Governing v1.4.6 design added.
- [x] Additive signup-attempt migration `0007_clerk_email_otp_onboarding_v1.4.6.sql` added.
- [x] `POST /security/v1/onboarding/users` changed to pre-authorization and no longer accepts password.
- [x] `POST /security/v1/onboarding/users/{signupAttemptId}/complete` added.
- [x] Clerk JWT identity is required for completion.
- [x] Clerk Backend User verification state is checked for the exact pre-authorized email.
- [x] First/last name can be synchronized to Clerk after email verification.
- [x] Security USER/external identity/onboarding request are created only after verified completion.
- [x] v1.4.5 backend-create registration path retired from the active service.
- [x] Unit tests updated for verified-email/profile synchronization contract.
- [x] Real PostgreSQL v1.4.6 acceptance test added.
- [x] Neon workflow applies migration 0007 and runs v1.4.6 acceptance.
- [ ] Security CI green on exact feature head.
- [ ] Neon/PostgreSQL green on exact feature head.
- [ ] PR merged to `dev`.
- [ ] Post-merge Security CI green.
- [ ] Railway DEV deployment green.
- [ ] Live Clerk email-OTP E2E completed with user inspection before cleanup.
- [ ] Dedicated v1.4.6 test report recorded.

## Acceptance invariant

> Verigence decides who may start signup; Clerk owns the password and email OTP; Security creates a PENDING global USER only after the authenticated Clerk identity proves ownership of the same pre-authorized email.
