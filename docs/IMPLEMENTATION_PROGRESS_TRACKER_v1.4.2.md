# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Date:** 2026-08-13

This tracker supersedes the execution pointer in `IMPLEMENTATION_PROGRESS_TRACKER_v1.4.1.md` where Clerk client/session assumptions conflict with v1.4.2.

Implementation authorities:

- `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
- `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`, except where superseded below;
- `docs/SECURITY_CLERK_BACKEND_FACADE_DESIGN_v1.4.2.md` — current human-authentication authority;
- `docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md`;
- `docs/SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md`;
- Security v1.3 normative artifacts for unchanged legacy/runtime scope.

## 1. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build/dependency checks |
| Phase 2 Neon DEV | DONE | Real PostgreSQL validation |
| Phase 3 Railway DEV | DONE | Exact immutable deployment + readiness/liveness/correlation |
| Phase 4 USER device/session lifecycle | PARTIAL / CONTRACT BOUNDARY | Internal lifecycle substantially complete |
| Admin Increment A | DONE | Control-plane persistence/catalogues |
| Increment B | DONE / AUTH TRANSITION REQUIRED | Direct Tenant APIs valid; local Platform password auth is transitional debt |
| Increment C | DONE | Module Catalogue + DI sync |
| Increment D | DONE | Groups + effective RBAC |
| Increment E | DONE | Tenant Role Admin APIs |
| Increment F | DONE | Invitation/acceptance + self-onboarding + first Owner bootstrap flows |
| Clerk backend-facade integration | NOW | Mobile/Web -> Verigence only; Security -> Clerk Backend API server-to-server |
| Increment G maker-checker | PAUSED | Resume only after backend Clerk cutover/E2E is green |
| Increment H Control Registry/runtime APIs | PENDING | After G unless explicitly resequenced |
| Increment I DI alignment | PENDING | Recorded DI corrections |
| Increment J Security -> DI E2E | PENDING | Final integration proof |

## 2. Completed Admin evidence retained

### Increment C — PR #43

```text
Real Neon:       31697061424 — PASS
Merge commit:    5ae78f90759c565e359e407cd032a83d7c18fe57
PR Security CI:  31699750982 — PASS
Railway DEV:     31699886154 — PASS
```

### Increments D/E — PR #44

```text
Final Neon:      31706796721 — PASS
PR Security CI:  31706801264 — PASS
Merge commit:    f1fb7c9dab8a11773b85d9fbc09b7c14ec705ea4
Post-merge CI:   31706985353 — PASS
Railway DEV:     31706985322 — PASS
```

### Increment F — PR #45

```text
Merge commit:    92544b424d9820f8822224b0002f5af58a632185
Status:          merged / Neon + Security CI + Railway promoted
```

### Clerk identity design amendment — PR #46

```text
Merge commit:    776763230a945d767d55e5f65b35e57c4fe3bd5c
PR Security CI:  PASS
```

v1.4.2 now refines the runtime architecture: clients do not receive Clerk sessions or call Clerk APIs directly.

## 3. Clerk backend-facade — NOW

### Frozen network rule

```text
Mobile/Web -> Verigence Security -> Clerk Backend API
```

No client Clerk SDK/direct Clerk call is permitted.

### Clerk responsibilities

- human credential/user storage;
- backend user creation;
- password verification;
- TOTP/backup-code verification when enabled;
- other explicitly approved Clerk backend identity operations.

### Security responsibilities

- public login/onboarding APIs;
- transient handling of credentials without persistence/logging;
- Clerk subject -> Security USER mapping;
- Platform roles;
- Tenant memberships;
- Groups/RBAC;
- device/geo/location/schedule/network controls;
- Security access sessions;
- Verigence Security JWTs;
- onboarding/Admin approval;
- audit.

### Environment contract

Backend deployment configuration will include:

```text
CLERK_SECRET_KEY=<Railway secret, never Git>
CLERK_BACKEND_API_URL=https://api.clerk.com/v1
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=<Railway configuration>
PLATFORM_BOOTSTRAP_ENABLED=<true only for first bootstrap>
```

`.env.example` contains placeholders/documentation only. Actual values never enter Git.

Former local bootstrap configuration is deprecated after cutover:

```text
PLATFORM_BOOTSTRAP_LOGIN
PLATFORM_BOOTSTRAP_PASSWORD
```

### Implementation sequence

```text
1. v1.4.2 design/tracker
2. environment configuration
3. Clerk Backend API adapter
4. backend Platform Super Admin bootstrap claim
5. backend Platform Admin credential login -> Security Admin JWT
6. disable normal local Platform password auth
7. normal USER backend login -> existing Security access-session policy
8. self-onboarding backend Clerk creation/binding
9. invitation backend Clerk creation/verification/binding
10. Neon + CI
11. Railway DEV
12. live Clerk Backend API E2E
13. evidence/tracker update
14. resume G
```

## 4. Important Clerk backend-only limitation

Official Clerk Backend `createUser()` marks supplied email/phone values verified. Therefore this increment does not
claim independent Clerk email/phone ownership verification.

If email/SMS OTP verification becomes required, a separate approved design must add an appropriate Clerk Frontend
API custom flow/proxy through the Verigence domain without permitting direct client-to-Clerk communication.

## 5. Current execution pointer

**NOW:** implement Clerk backend facade on `feature/clerk-backend-facade`.

**DO NOT:** resume maker-checker G until Clerk backend authentication, first Super Admin bootstrap, normal USER access,
self-onboarding/invitation identity paths, Neon/CI, Railway and live Clerk E2E are green and documented.
