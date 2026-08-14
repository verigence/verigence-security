# Phase 1 Clerk Email OTP Validation Plan v1.4.6

## Automated feature validation

Security CI must prove:
- Security onboarding request schema has no password field;
- v1.4.5 `register()` backend-create path is retired;
- Clerk backend adapter recognizes only exact `verification.status=verified` email matches;
- profile sync contains only first and last name;
- all existing unit/API tests remain green.

Real Neon/PostgreSQL must prove:
- migration 0007 applies idempotently;
- invalid onboarding key creates neither signup attempt nor USER;
- valid start creates `AUTHORIZED_FOR_CLERK` attempt and no USER;
- duplicate live email/mobile attempts are denied;
- unverified Clerk email cannot complete and creates no USER;
- verified matching Clerk email completes exactly once;
- completion creates USER=PENDING, principal=ACTIVE, CLERK mapping=ACTIVE and onboarding request=PENDING_ADMIN_APPROVAL;
- completed attempt cannot be replayed;
- historical Tenant authorization and Super Admin tests remain green.

## Live DEV E2E

Use a unique Gmail plus alias delivered to `gigsinopensource@gmail.com`.

1. Start signup through deployed Verigence API with the real DEV onboarding key.
2. Use Clerk's frontend sign-up flow with the same email and a disposable password.
3. Confirm Clerk sends an email OTP to the Gmail mailbox.
4. User supplies the OTP to Clerk; Verigence must never receive the OTP.
5. Finalize Clerk signup/session.
6. Complete Verigence signup using the Clerk session JWT.
7. Verify Security USER=PENDING and Clerk email verification status=verified.
8. **Pause. Do not delete.** User inspects the Clerk Dashboard entry.
9. After explicit user confirmation, delete the disposable Clerk user and all associated Security/signup/onboarding/audit/principal rows.
10. Verify zero residual records in Clerk and Security.

The live test is not complete until both the creation proof and cleanup proof are recorded.
