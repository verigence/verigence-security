# Verigence Security — Implementation Status

**Repository:** `verigence/verigence-security`  
**Current integration branch:** `dev`  
**Current implementation authority:** Security v1.3 + Admin Control Plane v1.4 + Clerk boundary v1.4.1 + Global USER Onboarding v1.4.2  
**Last updated:** 2026-08-14

Detailed current execution/evidence is maintained in:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## 1. Promoted baseline

The promoted `dev` baseline before the v1.4.2 correction is:

```text
0464adf353bf23cd7acf85db4368c3d456a06b34
```

That baseline includes:

- Security CI, Neon/PostgreSQL and Railway DEV foundations;
- USER device/access-session security controls;
- Platform Admin Control Plane increments A–F historical implementation;
- module permission catalogue and role templates;
- Groups and effective Tenant RBAC;
- Tenant Role administration;
- Clerk-backed Platform Super Admin bootstrap/login boundary;
- local Platform password runtime path disabled;
- immutable GHCR -> Railway exact-digest deployment.

The Clerk v1.4.1 merge/deployment evidence is retained in
`docs/CLERK_IDENTITY_INTEGRATION_TEST_REPORT_v1.4.1.md`.

## 2. Current architecture correction — v1.4.2

The previously implemented Tenant-scoped human invitation/self-onboarding identity model is superseded for the
active runtime.

The governing invariant is now:

> **A human is onboarded into Verigence once at Platform level. Tenant access is authorization assignment, not
> identity onboarding.**

### Global USER identity/lifecycle

Security owns:

- one global Security USER record;
- one-time global onboarding workflow;
- global onboarding key;
- `PENDING`, `ACTIVE`, `SUSPENDED`, `DISABLED`, `EXITED` USER lifecycle;
- Security Admin activation;
- Clerk external-identity mapping;
- lifecycle synchronization to Clerk;
- Verigence authorization and access tokens.

Clerk owns:

- password/passkey;
- email verification;
- MFA;
- recovery;
- authentication sessions;
- Clerk signed session JWTs.

### Tenant authorization

An ACTIVE global USER can be assigned independently in any number of Tenants through:

- direct Tenant roles;
- Groups and Group-inherited roles;
- explicit locations;
- schedules;
- registered devices and access controls.

`security.tenant_memberships` is no longer an active USER authorization/access-session prerequisite under v1.4.2.
Historical rows/tables remain until a separate retention migration is approved.

Per-user/per-Tenant authorization invalidation moves to:

```text
security.user_tenant_authorization_state
```

## 3. Current feature branch

```text
feature/global-user-onboarding-v1.4.2
```

Implemented in the branch:

- `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
- additive migration `0003_global_user_onboarding_v1.4.2.sql`;
- global USER `PENDING` lifecycle;
- single retrievable/rotatable/disable-able Platform onboarding key;
- Argon2id key validation + encrypted reveal material;
- Security validation and PENDING USER commit before Clerk provisioning;
- Clerk application invitation/profile/ban/unban adapter;
- authenticated Clerk binding to the pending Security USER;
- Security Admin USER activation/status management;
- public pre-auth allow/deny gate;
- Tenant creation decoupled from user onboarding;
- Tenant-scoped human onboarding routes removed from active runtime;
- Tenant RBAC gate without membership prerequisite;
- USER access sessions with nullable/unused membership ID;
- per-user/per-Tenant authorization version state;
- real PostgreSQL acceptance test for global one-time onboarding and cross-Tenant authorization.

**Status:** UNDER CI/NEON VALIDATION. Do not call v1.4.2 DONE until the current exact feature head is green.

## 4. Active route direction

New v1.4.2 global USER surfaces:

```text
GET    /security/v1/platform/user-onboarding/key
PUT    /security/v1/platform/user-onboarding/key
POST   /security/v1/platform/user-onboarding/key/rotate
DELETE /security/v1/platform/user-onboarding/key

POST   /security/v1/onboarding/users
POST   /security/v1/onboarding/users/{requestId}/bind
POST   /security/v1/auth/precheck

GET    /security/v1/platform/users
PATCH  /security/v1/platform/users/{userId}/status
```

Retired from active runtime:

- Tenant owner identity invitation;
- Tenant-scoped self-onboarding key/token;
- Tenant-scoped human invitations used for identity creation;
- Tenant self-registration/onboarding approval endpoints.

## 5. Remaining genuine blockers/deferred items

Unchanged blockers/deferred work include:

- complete SEC-032 Tenant activation prerequisite catalogue and activation mutation;
- persistent cross-replica idempotency store;
- device `BLOCKED` versus `REVOKED` business mutation semantics;
- legacy v1.3 lifecycle public route shapes dependent on the unavailable v1.3 OpenAPI;
- exact recent-MFA freshness requirement for privileged mutations;
- Clerk webhook lifecycle semantics beyond explicit v1.4.2 ban/unban synchronization;
- SYSTEM/SERVICE_INTEGRATION credential/token implementation;
- retention purge/offboarding execution;
- overlapping JWKS rotation;
- WPM permission catalogue until WPM is reviewed;
- UAT/Production readiness.

## 6. Live Clerk configuration still required

No secret values belong in Git.

For the live global onboarding/lifecycle path, deployment needs:

```text
CLERK_SECRET_KEY
SECURITY_USER_ONBOARDING_KEY_ENCRYPTION_KEY
```

The v1.4.1 Clerk issuer/public-key configuration remains required.

The real first Platform Super Admin bootstrap additionally still needs the intended immutable Clerk `user_...`
identifier. No placeholder is used for a live claim.

## 7. Current execution direction

```text
v1.4.2 design + implementation
       ↓
Security CI
       ↓
real Neon/PostgreSQL tests
       ↓
PR -> dev
       ↓
exact-commit CI
       ↓
immutable GHCR image
       ↓
Railway DEV
       ↓
health/correlation proof
       ↓
live Clerk E2E when required Clerk IDs/secrets are configured
```

Increment G maker-checker remains paused until this corrected identity/authorization foundation is green.
