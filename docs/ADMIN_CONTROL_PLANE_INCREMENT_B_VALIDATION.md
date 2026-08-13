# Admin Control Plane v1.4 — Increment B Validation

**Status:** DONE / PROMOTED / DEPLOYED  
**Date:** 2026-08-13  
**PR:** #41  
**Promoted DEV commit:** `44a3a868d82d03cdb4bca9250a6ce14769d9db8a`

## Scope validated

Increment B implements the Platform Super Admin and direct Tenant-administration runtime defined by the approved
Admin Control Plane v1.4 design.

Validated capabilities:

- deployment-controlled, idempotent Platform Super Admin bootstrap;
- bootstrap login and password supplied only through deployment configuration/secrets;
- Argon2id password hashing with no plaintext credential persistence;
- restart does not reset an existing Platform Super Admin password;
- bootstrap account starts with `must_change_password=true`;
- dedicated Platform Admin JWT with audience `verigence-security-admin`;
- Platform Admin token contains no Tenant/access-session business context;
- Platform login, mandatory password change and `/me` APIs;
- permission-protected direct Tenant create/list/get/update APIs;
- new Tenant starts in `CONFIGURING` state;
- all eight reserved Tenant Admin roles and exact v1.4 bundles are seeded in the Tenant provisioning transaction;
- optional self-onboarding token supplied during Tenant creation is Argon2id-hashed and never persisted in plaintext;
- structured `admin_change_records` are written for bootstrap, password and Tenant mutations;
- Tenant activation is not exposed and remains fail-closed under OPEN-010.

## API surface promoted

```text
POST  /security/v1/platform/auth/login
POST  /security/v1/platform/auth/change-password
GET   /security/v1/platform/me
POST  /security/v1/platform/tenants
GET   /security/v1/platform/tenants
GET   /security/v1/platform/tenants/{tenantId}
PATCH /security/v1/platform/tenants/{tenantId}
```

Tenant mutation authorization uses the frozen v1.4 `security.tenant.*` Platform permissions.

## Validation evidence

```text
Final feature head:              6bff9941417d490856f80d18aa8a2d20455e2ffd
Final-head real-Neon validation: 31694765879 — 16/16 PASS
PR Security CI:                  31694771302 — PASS
PR:                              #41 — MERGED
Promoted DEV commit:             44a3a868d82d03cdb4bca9250a6ce14769d9db8a
Post-merge Security CI:          31694931046 — PASS
Railway DEV deployment/smoke:    31694931027 — PASS
```

The Railway workflow passed:

- exact-commit Security CI gate;
- immutable GHCR image build;
- immutable image validation;
- Railway DEV scope verification;
- exact image attachment to the DEV service instance;
- Railway deployment `SUCCESS`;
- `/health/ready`;
- `/health/live`;
- `X-Correlation-ID` propagation.

## Security properties retained

- no bootstrap password value exists in Git or this evidence document;
- Platform Admin credentials are separate from Tenant/user external identity credentials;
- Platform Admin JWT is not a DI/WPM business token;
- Platform Super Admin does not automatically receive `di.*`, `wpm.*`, or other business-module permissions;
- direct Tenant creation does not activate a Tenant;
- self-onboarding token configuration does not itself grant a USER Tenant access.

## Next increment

Admin Control Plane v1.4 Increment C:

```text
Module Catalogue API
  -> module registration/update
  -> module namespace enforcement
  -> permission lifecycle/catalogue synchronization
  -> module role-template synchronization
  -> initial Document Intelligence catalogue synchronization
  -> real Neon + Security CI + Railway validation
```
