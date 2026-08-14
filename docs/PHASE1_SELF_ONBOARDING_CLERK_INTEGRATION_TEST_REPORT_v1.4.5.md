# Verigence Security — Phase 1 Self-Onboarding and Clerk Integration Test Report v1.4.5

**Date:** 2026-08-14  
**Repository:** `verigence/verigence-security`  
**Environment:** DEV  
**Result:** PASS

## 1. Scope

This report covers the Phase 1 self-onboarding correction governed by:

```text
docs/SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md
```

The promoted contract is:

```text
one self-registration request to Verigence Security
  -> validate Platform onboarding key
  -> validate globally unique email + Indian mobile
  -> Clerk Backend POST /v1/users
  -> Clerk returns immutable user_...
  -> Security creates global USER=PENDING + CLERK mapping
  -> onboarding request=PENDING_ADMIN_APPROVAL
  -> Security Admin/Super Admin later activates USER
```

Phase 1 uses email as the sign-in identifier. Indian mobile is Verigence-only. There is no Clerk invitation, separate username, dummy Clerk phone number, active `/bind` endpoint, Tenant onboarding or MFA.

## 2. API contract validated

Public registration:

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <Platform global onboarding key>
```

Request body:

```json
{
  "firstName": "Amit",
  "lastName": "Goyal",
  "email": "amit@example.com",
  "mobile": "+919876543210",
  "password": "<transient password>"
}
```

Security -> Clerk creation payload is restricted to:

```json
{
  "first_name": "Amit",
  "last_name": "Goyal",
  "email_address": ["amit@example.com"],
  "password": "<transient password>"
}
```

No `phone_number` or `username` is sent to Clerk.

## 3. Schema/migration validation

Additive migration:

```text
migrations/0006_phase1_self_onboarding_v1.4.5.sql
```

Validated on real Neon/PostgreSQL:

- first/last name persistence supported;
- email remains globally unique case-insensitively;
- normalized mobile uniqueness is enforced at database level;
- historical migrations remain intact and idempotent;
- existing global USER/Tenant authorization and Super Admin behavior remains compatible.

## 4. Feature-head validation

```text
Feature branch:           feature/phase1-self-onboarding-clerk-v1.4.5
Feature head:             fd72e24d833ad28c129cff185656719b699177c8
PR:                       #54
Security CI:              31779990307 — PASS
Real Neon/PostgreSQL:     31779986825 — PASS
```

Security CI passed:

- approved-design/static safety;
- Python compilation;
- Ruff;
- Mypy;
- active runtime route contract;
- automated tests;
- package build;
- installed dependency consistency.

## 5. Real PostgreSQL Phase 1 acceptance evidence

The v1.4.5 Neon acceptance test proved:

1. invalid onboarding key results in no Clerk create call and no Security USER;
2. correct onboarding key is validated before Clerk creation;
3. email is normalized to lower case;
4. Indian mobile is normalized to canonical `+91XXXXXXXXXX`;
5. successful Clerk creation precedes Security USER persistence;
6. Security USER is created with status `PENDING`;
7. CLERK external identity is created from Clerk's immutable `user_...` subject;
8. onboarding request is created as `PENDING_ADMIN_APPROVAL`;
9. no Clerk invitation ID is created;
10. duplicate email is rejected before Clerk creation;
11. duplicate normalized mobile is rejected before Clerk creation;
12. database-level mobile uniqueness guard exists;
13. a post-Clerk Security persistence collision invokes Clerk delete compensation;
14. the failed local transaction leaves no second Security USER;
15. pre-authentication check remains false while USER status is PENDING;
16. historical global USER/cross-Tenant authorization regression remains green;
17. built-in Super Admin full-authority regression remains green;
18. retained historical Phase 5 administration tests remain green.

## 6. Clerk adapter unit evidence

Automated unit tests prove that `ClerkBackendClient.create_user()`:

- calls the Clerk Backend `/v1/users` endpoint;
- sends first name;
- sends last name;
- sends email address;
- sends the submitted password only for immediate Clerk creation;
- sends no phone number;
- sends no username.

The compensation test proves `ClerkBackendClient.delete_user()` targets `/v1/users/{user_id}`.

## 7. Password boundary

The implementation does not persist a password in Security tables or audit/event records.

The approved Phase 1 boundary is:

```text
client -> HTTPS -> Verigence Security -> HTTPS -> Clerk Backend
```

The plaintext password is transient registration transport only. Security does not authenticate it or maintain a password hash. Application logging/tracing must continue to redact request-body password fields.

## 8. Active route contract

The runtime route contract confirms these Phase 1/global USER routes remain active:

```text
POST  /security/v1/onboarding/users
POST  /security/v1/auth/precheck
GET   /security/v1/platform/users
PATCH /security/v1/platform/users/{userId}/status
```

The historical Clerk binding endpoint is absent from active OpenAPI:

```text
/security/v1/onboarding/users/{requestId}/bind
```

Historical Tenant-scoped onboarding endpoints remain retired.

## 9. Promotion evidence

```text
PR #54:                  MERGED
Promoted DEV commit:     7765e72a6078a15981cffb42c0d7e3bdbdc269de
Post-merge Security CI:  31780116228 — PASS
Railway DEV:             31780116188 — PASS
readiness:               PASS
liveness:                PASS
correlation ID:          PASS
```

The Railway pipeline validated the exact `dev` commit, built/published the immutable image, attached that exact image to Railway DEV, waited for successful deployment, and passed readiness/liveness/correlation verification.

## 10. Result

**Phase 1 self-onboarding and the Verigence -> Clerk Backend user-creation integration are implemented, tested, merged and deployed to DEV.**

The remaining environment prerequisite for a live real-user creation through this endpoint is that the deployed Security service has a valid backend-only `CLERK_SECRET_KEY` for the same Clerk instance. The key must remain outside source control.

MFA remains explicitly deferred to Phase 2.
