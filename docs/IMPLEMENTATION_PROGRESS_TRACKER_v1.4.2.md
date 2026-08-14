# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted runtime code commit:** `951a7694b31c195ccbde45d13346e0eea8ae9f14`  
**Current branch under validation:** `feature/phase1-self-onboarding-clerk-v1.4.5`  
**Date:** 2026-08-14

## 1. Implementation authorities

Read/apply in this order when decisions conflict:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md` for normal Phase 1 human self-registration and Verigence <-> Clerk API integration;
3. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md` for fresh-environment initial administrator provisioning;
4. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md` for built-in Super Admin authority;
5. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for unchanged global USER lifecycle and Tenant authorization rules not superseded by v1.4.5;
6. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk authentication ownership;
7. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin Control Plane scope;
8. Security v1.3 normative artifacts for unchanged runtime scope;
9. this tracker for current execution/evidence.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build and dependency checks enforced |
| Phase 2 Neon DEV | DONE | Real PostgreSQL regression suite green through v1.4.4 hotfix; v1.4.5 validation pending |
| Phase 3 Railway DEV | DONE | Exact-commit immutable deployment with readiness/liveness/correlation proof |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Clerk remains the human authentication provider |
| Global USER onboarding v1.4.2 | DONE / DEPLOYED / FLOW AMENDED BY v1.4.5 | USER onboarding remains Platform-global and one-time; invitation/bind steps are superseded |
| Phase 1 self-onboarding + Clerk integration v1.4.5 | UNDER VALIDATION | Single-submit Security-first validation -> Clerk create -> Security PENDING USER |
| Built-in Platform Super Admin authority v1.4.3 | DONE / DEPLOYED | Full current/future permission authority and Tenant provisioning authority validated |
| Initial Super Admin system provisioning v1.4.4 | DONE / PROVISIONED / DEPLOYED | Selected Clerk identity is ACTIVE Security Super Admin in DEV |
| Increment G maker-checker | PAUSED | Resume after v1.4.5 self-onboarding correction is promoted |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Frozen identity and authorization model

```text
Normal human onboarding  = Platform-global, one time per person
Phase 1 registration     = self-onboarding with shared Platform onboarding key
Sign-in identifier       = email address; no separate username
Indian mobile            = Verigence-only; never sent to Clerk in Phase 1
MFA                      = deferred to Phase 2
Tenant access             = authorization assignment, not identity onboarding
Clerk                     = credential/authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Initial administrator     = controlled system provisioning from immutable Clerk user_ ID
Platform Super Admin      = built-in role with every ACTIVE Security permission
```

The same ACTIVE global Security USER may receive different Tenant-scoped roles/groups/locations/schedules in multiple Tenants without another onboarding event.

## 4. Phase 1 self-onboarding v1.4.5 — CURRENT WORKSTREAM

The authoritative registration sequence is:

```text
User submits onboarding key + first name + last name + email + Indian mobile + password
  -> Security validates key and global email/mobile uniqueness
  -> Security calls Clerk POST /v1/users with name + email + password only
  -> Clerk returns immutable user_...
  -> Security creates global USER=PENDING + CLERK mapping + PENDING_ADMIN_APPROVAL request
  -> user receives pending-approval response
  -> Security Admin/Super Admin later activates USER
```

There is no active Clerk invitation or later `/onboarding/users/{requestId}/bind` step. No Tenant data is collected during onboarding.

Phase 1 API contract:

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <global key>

body:
  firstName
  lastName
  email
  mobile
  password
```

The password is transient transport data only: HTTPS, never stored/hashed/logged/audited by Security, and forwarded only to Clerk Backend user creation.

v1.4.5 implementation introduces:

- `ClerkBackendClient.create_user()` using `POST /v1/users`;
- `ClerkBackendClient.delete_user()` for compensation;
- additive migration `0006_phase1_self_onboarding_v1.4.5.sql`;
- `security.users.first_name` and `last_name`;
- database-level normalized mobile uniqueness;
- dedicated single-submit onboarding service;
- retirement of the active `/bind` route;
- unit and real Neon/PostgreSQL acceptance tests.

## 5. v1.4.5 acceptance gates

Before merge/promotion:

- design/static integrity green;
- Security CI green on the exact feature head;
- unit test proves Clerk payload contains name/email/password and no phone/username;
- invalid onboarding key makes no Clerk call;
- duplicate email makes no Clerk call;
- duplicate normalized mobile makes no Clerk call;
- successful Clerk create persists exactly one Security USER=PENDING and CLERK mapping;
- onboarding request becomes PENDING_ADMIN_APPROVAL;
- Security persistence failure invokes Clerk delete compensation;
- active OpenAPI contains no `/onboarding/users/{requestId}/bind`;
- existing global USER/Tenant authorization and Super Admin regressions remain green;
- real Neon/PostgreSQL validation passes after migration 0006.

After merge:

- exact-commit Security CI green;
- Railway DEV exact-digest deployment green;
- readiness/liveness/correlation checks green;
- canonical tracker/test report updated to DONE / DEPLOYED.

## 6. v1.4.4 DEV initial administrator — COMPLETED

Selected Clerk identity:

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Platform role:     platform.super_admin
```

Provisioned Security state was verified as:

```text
Security principal        ACTIVE
Global Security USER      ACTIVE
CLERK external identity   ACTIVE
platform.super_admin      ACTIVE
Missing ACTIVE permissions from Super Admin = 0
```

No Tenant membership, Tenant role or local password credential was created for the initial administrator.

Fresh installation does not require the initial person to perform `/security/v1/platform/bootstrap/claim`. The historical claim implementation remains disabled unless an explicit compatibility/migration procedure requires it.

Promotion evidence:

```text
PR #52 feature head:      ae64a9fa0bd2781aeb9840b6c0e9b77aaf0f244c
Feature Security CI:      31776200341 — PASS
Feature Neon/PostgreSQL:  31776189798 — PASS
PR #52:                   MERGED
Promoted runtime commit:  951a7694b31c195ccbde45d13346e0eea8ae9f14
Post-merge Security CI:   31776274556 — PASS
DEV provisioning:         31776274559 — PASS
Railway DEV:              31776274539 — PASS
readiness/liveness/correlation: PASS
```

Detailed evidence is recorded in `docs/INITIAL_SUPER_ADMIN_PROVISIONING_TEST_REPORT_v1.4.4.md`.

## 7. Current execution pointer

```text
feature/phase1-self-onboarding-clerk-v1.4.5
  -> Security CI + real Neon/PostgreSQL
  -> PR -> dev
  -> exact-commit Security CI
  -> immutable GHCR image -> Railway DEV
  -> readiness/liveness/correlation
  -> record v1.4.5 test evidence
  -> resume Increment G maker-checker
```

Do not reintroduce Clerk invitations, Tenant-scoped human onboarding, Tenant membership for USER onboarding, a separate Phase 1 username, dummy Clerk phone numbers, or Phase 1 MFA.
