# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted runtime code commit:** `951a7694b31c195ccbde45d13346e0eea8ae9f14`  
**Date:** 2026-08-14

## 1. Implementation authorities

Read/apply in this order when decisions conflict:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md` for fresh-environment initial administrator provisioning;
3. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md` for built-in Super Admin authority;
4. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for normal global USER onboarding/lifecycle;
5. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk authentication ownership;
6. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin Control Plane scope;
7. Security v1.3 normative artifacts for unchanged runtime scope;
8. this tracker for current execution/evidence.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build and dependency checks enforced |
| Phase 2 Neon DEV | DONE | Real PostgreSQL regression suite green through v1.4.4 hotfix |
| Phase 3 Railway DEV | DONE | Exact-commit immutable deployment with readiness/liveness/correlation proof |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Clerk remains the human authentication provider |
| Global USER onboarding v1.4.2 | DONE / DEPLOYED | USER onboarding is Platform-global and one-time |
| Built-in Platform Super Admin authority v1.4.3 | DONE / DEPLOYED | Full current/future permission authority and Tenant provisioning authority validated |
| Initial Super Admin system provisioning v1.4.4 | DONE / PROVISIONED / DEPLOYED | Selected Clerk identity is ACTIVE Security Super Admin in DEV |
| Increment G maker-checker | NEXT | Initial administrator provisioning dependency is closed; normal Clerk login E2E can be exercised from the separate UI/auth client |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Frozen identity and authorization model

```text
Normal human onboarding  = Platform-global, one time per person
Tenant access             = authorization assignment, not identity onboarding
Clerk                     = human authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Initial administrator     = controlled system provisioning from immutable Clerk user_ ID
Platform Super Admin      = built-in role with every ACTIVE Security permission
```

The same ACTIVE global Security USER may receive different Tenant-scoped roles/groups/locations/schedules in multiple Tenants without another onboarding event.

## 4. v1.4.4 DEV initial administrator — COMPLETED

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

## 5. v1.4.4 promotion and test evidence

Initial implementation:

```text
PR #51 feature head:      a3cd8189222993c76c1dc8e5d8908629e8c66f1c
Feature Security CI:      31775948471 — PASS
Feature Neon/PostgreSQL:  31775946314 — PASS
PR #51:                   MERGED
Initial DEV commit:       4e65c79b87dd3f504ff4909de408689474b6f1b0
Post-merge Security CI:   31776049176 — PASS
First provisioning run:   31776049219 — FAIL / TRANSACTION ROLLED BACK
```

The first provisioning attempt exposed a PostgreSQL bind-type ambiguity in the audit insert (`actor_user_id` UUID versus `resource_id` varchar). The transaction rolled back; no partial Super Admin data was retained.

Hotfix and successful provisioning:

```text
PR #52 feature head:      ae64a9fa0bd2781aeb9840b6c0e9b77aaf0f244c
Feature Security CI:      31776200341 — PASS
Feature Neon/PostgreSQL:  31776189798 — PASS
PR #52:                   MERGED
Promoted runtime commit:  951a7694b31c195ccbde45d13346e0eea8ae9f14
Post-merge Security CI:   31776274556 — PASS
DEV provisioning:         31776274559 — PASS
Railway DEV:              31776274539 — PASS
readiness:                PASS
liveness:                 PASS
correlation ID:           PASS
```

The provisioning workflow directly verified the resulting Security mapping and full permission coverage after commit.

Detailed evidence is also recorded in `docs/INITIAL_SUPER_ADMIN_PROVISIONING_TEST_REPORT_v1.4.4.md`.

## 6. Current execution pointer

Initial Security-side system provisioning is complete.

The next functional sequence is:

```text
provisioned Clerk Super Admin
  -> normal Clerk authentication from the separate UI/auth client
  -> Clerk session JWT
  -> Security Platform Admin login/token exchange
  -> verify /platform/me and full effective authority
  -> Increment G maker-checker
```

Do not ask for a Clerk password, secret key or session token to be stored in Git. Runtime authentication must remain a normal Clerk flow.

Do not reintroduce Tenant-scoped human onboarding, Tenant membership for USER onboarding, or redundant Tenant-role provisioning for the Platform Super Admin.
