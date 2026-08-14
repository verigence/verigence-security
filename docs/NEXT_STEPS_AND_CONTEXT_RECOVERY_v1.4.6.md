# Verigence Security — Next Steps and Context Recovery v1.4.6

**Current increment:** Clerk-owned email OTP self-onboarding v1.4.6  
**Status:** UNDER VALIDATION

## Authoritative design

Read first:

`docs/SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md`

Do not reconstruct the superseded v1.4.5 single-submit backend Clerk-create flow as the active model.

## Active API

```text
POST /security/v1/onboarding/users
  -> validates onboarding key + identity fields
  -> creates short-lived signupAttemptId
  -> HTTP 202 / CLERK_EMAIL_VERIFICATION_REQUIRED

Client -> Clerk
  -> password signup
  -> send email OTP
  -> verify email OTP
  -> finalize Clerk session

POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
  -> verifies Clerk session
  -> verifies exact email has Clerk verification.status=verified
  -> creates Security USER=PENDING
  -> creates CLERK external identity
  -> creates PENDING_ADMIN_APPROVAL request
```

## Phase 1 invariants

- email is sign-in ID;
- Indian mobile is Verigence-only;
- no dummy Clerk phone;
- password is never sent to Security;
- email OTP is owned by Clerk;
- MFA remains Phase 2;
- onboarding is global and once per person;
- no Tenant membership is required;
- Security Admin/Super Admin activation remains authoritative.

## Next actions

1. Obtain exact-head Security CI green.
2. Obtain exact-head Neon/PostgreSQL green including migration 0007 and v1.4.6 acceptance.
3. Merge to `dev` only after both gates pass.
4. Validate post-merge Security CI and Railway DEV.
5. Run live Clerk E2E using `gigsinopensource+verigence-e2e-<unique>@gmail.com`.
6. Pause after Clerk account + OTP verification + Security PENDING creation so the user can inspect Clerk.
7. Delete the disposable Clerk identity and every associated Security/signup/audit record only after user confirmation.
8. Record final v1.4.6 test evidence.
