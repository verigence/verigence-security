# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted runtime code commit:** `7765e72a6078a15981cffb42c0d7e3bdbdc269de`  
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
| Phase 2 Neon DEV | DONE | Real PostgreSQL regression suite green through v1.4.5 |
| Phase 3 Railway DEV | DONE | Exact-commit immutable deployment with readiness/liveness/correlation proof |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Clerk remains the human credential/authentication provider |
| Global USER onboarding v1.4.2 | DONE / DEPLOYED / FLOW AMENDED BY v1.4.5 | USER onboarding remains Platform-global and one-time |
| Phase 1 self-onboarding + Clerk integration v1.4.5 | DONE / DEPLOYED | Single-submit Security validation -> Clerk create -> Security PENDING USER |
| Built-in Platform Super Admin authority v1.4.3 | DONE / DEPLOYED | Full current/future permission authority and Tenant provisioning authority validated |
| Initial Super Admin system provisioning v1.4.4 | DONE / PROVISIONED / DEPLOYED | Selected Clerk identity is ACTIVE Security Super Admin in DEV |
| Increment G maker-checker | NEXT | v1.4.5 onboarding correction is promoted; proceed with maker-checker |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Frozen Phase 1 identity/onboarding model

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
```

The same ACTIVE global Security USER may receive different Tenant-scoped roles/groups/locations/schedules in multiple Tenants without another onboarding event.

## 4. Phase 1 self-onboarding v1.4.5 — DONE / DEPLOYED

Authoritative registration sequence:

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

Active API contract:

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

Implementation includes:

- `ClerkBackendClient.create_user()` using `POST /v1/users`;
- `ClerkBackendClient.delete_user()` for compensation;
- additive migration `0006_phase1_self_onboarding_v1.4.5.sql`;
- `security.users.first_name` and `last_name`;
- database-level normalized Indian mobile uniqueness;
- dedicated single-submit onboarding service;
- active retirement of the `/bind` route;
- unit and real Neon/PostgreSQL acceptance tests.

## 5. v1.4.5 promotion/test evidence

```text
Feature head:             fd72e24d833ad28c129cff185656719b699177c8
Feature Security CI:      31779990307 — PASS
Feature Neon/PostgreSQL:  31779986825 — PASS
PR #54:                   MERGED
Promoted DEV commit:      7765e72a6078a15981cffb42c0d7e3bdbdc269de
Post-merge Security CI:   31780116228 — PASS
Railway DEV:              31780116188 — PASS
readiness:                PASS
liveness:                 PASS
correlation ID:           PASS
```

Validated acceptance includes:

- invalid onboarding key -> no Clerk call/no USER;
- duplicate email -> no Clerk call;
- duplicate normalized mobile -> no Clerk call;
- Clerk payload contains first name/last name/email/password and no phone/username;
- successful Clerk creation -> exactly one Security USER=PENDING + CLERK mapping;
- onboarding request -> PENDING_ADMIN_APPROVAL;
- post-Clerk Security persistence collision -> Clerk delete compensation;
- PENDING USER precheck remains false;
- active OpenAPI contains no `/onboarding/users/{requestId}/bind`;
- historical global USER/cross-Tenant authorization remains green;
- Platform Super Admin regression remains green;
- retained Phase 5 PostgreSQL administration suite remains green.

Detailed report:

```text
docs/PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_TEST_REPORT_v1.4.5.md
```

## 6. Initial DEV Super Admin — COMPLETED

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Platform role:     platform.super_admin
```

Verified Security principal/USER/CLERK mapping/Super Admin role are ACTIVE with zero missing ACTIVE permissions.

## 7. Environment prerequisite for live Clerk creation

The deployed Phase 1 onboarding endpoint requires backend-only `CLERK_SECRET_KEY` for the same Clerk application instance. The value must remain in deployment-secret configuration and must never be committed to Git or returned to clients.

## 8. Current execution pointer

```text
v1.4.5 self-onboarding      DONE / DEPLOYED
       ↓
Increment G maker-checker   NEXT
       ↓
Increment H
       ↓
Increment I
       ↓
Increment J
```

Do not reintroduce Clerk invitations, Tenant-scoped human onboarding, Tenant membership for USER onboarding, a separate Phase 1 username, dummy Clerk phone numbers, or Phase 1 MFA.
