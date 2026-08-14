# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Branch under validation:** `feature/global-user-onboarding-v1.4.2`  
**Date:** 2026-08-14

This tracker supersedes execution pointers in `IMPLEMENTATION_PROGRESS_TRACKER.md` and
`IMPLEMENTATION_PROGRESS_TRACKER_v1.4.1.md`. Those files remain historical evidence.

## 1. Implementation authorities

Read/apply in this order when decisions conflict:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
3. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk boundary;
4. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin Control Plane scope;
5. Security v1.3 normative artifacts for unchanged runtime scope;
6. this tracker for current execution/evidence.

v1.4.2 specifically supersedes conflicting Tenant-scoped human-onboarding and
Tenant-membership-as-runtime-access-prerequisite decisions. It does not erase historical data or validation.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build and dependency checks enforced |
| Phase 2 Neon DEV | DONE | Real PostgreSQL validation available |
| Phase 3 Railway DEV | DONE | Immutable exact-commit deployment with health/correlation evidence |
| Phase 4 USER device/session lifecycle | PARTIAL / CONTRACT BOUNDARY | Internal lifecycle substantially complete; legacy v1.3 contract/idempotency blockers remain |
| Admin Control Plane A–E | DONE | Persistence, Platform admin, module catalogue, Groups and Tenant RBAC implemented |
| Increment F historical Tenant onboarding | SUPERSEDED FOR IDENTITY | Historical implementation retained; Tenant-scoped human identity onboarding is retired by v1.4.2 |
| Clerk identity cutover v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Clerk-backed Platform Admin boundary merged/deployed; live first-Super-Admin claim still requires real Clerk user ID |
| Global USER onboarding v1.4.2 | NOW | Design frozen; implementation branch under CI/Neon validation |
| Increment G maker-checker | PAUSED | Resume only after v1.4.2 and live Clerk identity E2E are green |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Previously promoted evidence retained

### Increments A–F

Historical PR/run/commit evidence remains in `IMPLEMENTATION_PROGRESS_TRACKER_v1.4.1.md` and the older tracker.

Increment F's Tenant invitation/self-onboarding implementation is historical implementation evidence only after
v1.4.2. Its identity/onboarding runtime endpoints must not remain active.

### Clerk v1.4.1 — PR #47

Merged/deployed evidence:

```text
Promoted DEV commit:  0464adf353bf23cd7acf85db4368c3d456a06b34
Post-merge Security CI: 31728164273 — PASS
Railway DEV run:        31728164126 — PASS
Immutable image:
  ghcr.io/verigence/verigence-security@
  sha256:b250d25a7f76116065d22654fb271a8a647a44c4c92fd36c618ef54d16f352f8
Railway deployment:     79f026f5-0bbf-4601-856b-a9a7f4e678c6
Railway DEV URL:        https://verigence-security-dev.up.railway.app
readiness:               PASS
liveness:                PASS
correlation ID:          PASS
```

Detailed report: `docs/CLERK_IDENTITY_INTEGRATION_TEST_REPORT_v1.4.1.md`.

This proves the Clerk-backed Platform boundary and deployment mechanism. It does not prove the revised global
USER onboarding flow introduced by v1.4.2.

## 4. Architecture correction — v1.4.2

Frozen invariant:

> USER onboarding is Platform-global and one-time. Tenant access is authorization assignment, not identity
> onboarding.

Required model:

```text
Global Security USER
  -> one Clerk mapping
  -> Security-owned USER lifecycle
  -> zero/many Tenant-scoped roles/groups/locations/schedules
```

Explicitly retired as active-runtime requirements:

- Tenant-scoped onboarding key/token;
- Tenant-specific human identity onboarding;
- re-onboarding when a USER needs another Tenant;
- Tenant membership as a prerequisite for USER authorization/access-session issuance.

Historical tables/rows remain until a separate destructive migration/retention decision is approved.

## 5. v1.4.2 implementation scope

Current branch must deliver and validate:

1. one retrievable/rotatable/disable-able Platform onboarding key;
2. Argon2id validation plus encrypted-at-rest reveal material;
3. Security key validation before any Clerk provisioning call;
4. global USER=`PENDING` creation before Clerk invitation;
5. Clerk application invitation integration;
6. Clerk JWT/profile binding to the pending global USER;
7. Security Admin-only activation;
8. Security lifecycle ban/unban synchronization with Clerk;
9. minimal pre-auth allow/deny check for future UI;
10. same global USER assignable across multiple Tenants;
11. no Tenant membership gate in Tenant RBAC/runtime access;
12. per-user/per-Tenant `user_tenant_authorization_state` versioning;
13. USER access session with `membership_id=NULL`;
14. old Tenant onboarding endpoints absent from active route table;
15. additive migration `0003_global_user_onboarding_v1.4.2.sql`;
16. real Neon/PostgreSQL validation;
17. Security CI;
18. exact-commit Railway DEV promotion after merge;
19. evidence/test-report update.

## 6. Current branch state

Branch:

```text
feature/global-user-onboarding-v1.4.2
```

Implemented in branch before validation:

- v1.4.2 governing design amendment;
- additive migration 0003;
- Platform-global onboarding-key persistence;
- global onboarding request persistence;
- Clerk Backend API invitation/profile/ban/unban adapter;
- global onboarding service and APIs;
- global USER lifecycle administration;
- pre-authentication allow/deny gate;
- Tenant creation decoupled from self-onboarding;
- Tenant onboarding routes removed from active runtime;
- Tenant RBAC authorization without membership prerequisite;
- runtime USER session without membership ID;
- per-user/per-Tenant authorization state and version bumps;
- Neon workflow extended to apply/test v1.4.2.

**VALIDATION STATUS:** IN PROGRESS. Do not mark v1.4.2 DONE until the required CI and Neon evidence below is
recorded.

## 7. Required v1.4.2 acceptance evidence

The feature is not DONE until tests prove:

- onboarding key set/reveal/rotate/disable;
- wrong/disabled key fails before Security USER creation and before Clerk call;
- correct key creates PENDING global USER then Clerk invitation;
- duplicate email is rejected;
- Clerk binding validates pending email/subject uniqueness;
- binding does not activate USER;
- admin activation -> USER ACTIVE + Clerk unban;
- suspension/disable -> Security sessions revoked + Clerk ban;
- precheck false for non-ACTIVE, true for ACTIVE mapped USER;
- Tenant role assignment works without tenant_memberships;
- one USER can be authorized in two Tenants without re-onboarding;
- runtime Tenant authorization works without membership;
- access session records membership_id NULL;
- authorization version changes in the affected USER/Tenant scope;
- retired Tenant onboarding routes are not registered;
- migration is repeatable/idempotent on Neon DEV;
- full Security CI passes on exact feature head.

Evidence placeholders:

```text
Feature head:          PENDING
Security CI:           PENDING
Real Neon/PostgreSQL:  PENDING
PR:                    PENDING
Promoted DEV commit:   PENDING
Post-merge CI:         PENDING
Railway DEV:           PENDING
```

## 8. Deployment configuration still required for live onboarding

No secret values belong in Git.

Required DEV deployment secrets/config for live lifecycle operations:

```text
CLERK_SECRET_KEY
CLERK_BACKEND_API_URL=https://api.clerk.com/v1
SECURITY_USER_ONBOARDING_KEY_ENCRYPTION_KEY
```

Clerk verification configuration from v1.4.1 remains required.

The first Platform Super Admin live bootstrap still additionally requires the intended immutable Clerk `user_...`
identifier. Do not use a placeholder for a live claim.

## 9. Current execution pointer

**NOW:** complete v1.4.2 code cleanup + tests + Security CI + real Neon validation.

Then:

```text
v1.4.2 PR -> dev
  -> exact-commit Security CI
  -> immutable GHCR image
  -> Railway DEV
  -> readiness/liveness/correlation
  -> live Clerk bootstrap/onboarding E2E when required Clerk IDs/secrets are configured
```

**PAUSED:** Increment G maker-checker until v1.4.2 plus the required live Clerk identity proof is green.

Do not restart Tenant-scoped human onboarding from v1.4/v1.4.1 documents after a context reset.
