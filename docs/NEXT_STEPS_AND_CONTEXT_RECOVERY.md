# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Phase 4 clarifications + Admin Control Plane v1.4  
**Last updated:** 2026-08-13

## 1. Governing rule

Implementation is grounded in approved/versioned Security artifacts, not chat reconstruction.

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`.
3. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
4. `docs/IMPLEMENTATION_STATUS.md`.
5. `docs/APPROVED_SOURCE_REFERENCE.md`.
6. `docs/SECURITY_DECISION_REGISTER_v1.3.md`.
7. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`.
8. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
9. `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.
10. `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.
11. Current Security `dev`, current DI `dev`, open PRs and CI/Railway state.

Do not invent behavior where v1.3/v1.4 still records an explicit blocker.

## 2. Current implementation position

### Phase 1 — CI

**DONE.**

### Phase 2 — Neon DEV

**DONE.**

### Phase 3 — Railway DEV

**DONE.**

### Phase 4 — USER device/session lifecycle

**SUBSTANTIALLY COMPLETE INTERNALLY / LEGACY CONTRACT BOUNDARY.**

Internal device/session persistence, device-limit concurrency, USER revoke, complete refresh re-evaluation,
approved location movement, denial evidence and non-ACTIVE device gating are implemented and validated.

Remaining old lifecycle public routes still depend on the unavailable v1.3 OpenAPI. Persistent idempotency and the
business distinction between device `BLOCKED` and `REVOKED` also remain unresolved.

### Phase 5 — Security administration foundation

**INTERNAL FOUNDATION DONE / ADMIN CONTROL PLANE IMPLEMENTATION NOW.**

Already implemented and deployed internally:

- Tenant Security Policy configuration;
- Security Retention Policy configuration;
- Tenant locations;
- schedules/windows;
- Security-side USER onboarding records;
- external identity mapping;
- Tenant membership;
- employee-location/schedule assignment;
- canonical permissions;
- Tenant roles/role-permission grants;
- direct user-role assignment;
- fail-closed activation-readiness foundation.

The new versioned Admin Control Plane design removes the former Admin API/permission design blocker.

## 3. Admin Control Plane v1.4 authority

`docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` is the implementation authority for:

- Platform Super Admin bootstrap/login;
- direct Platform Admin Tenant creation;
- standard Platform/Tenant administrator roles;
- exact `security.*` Admin permission catalogue;
- Tenant Groups;
- module catalogue and module role templates;
- module permission namespace ownership;
- Tenant role/template behavior;
- RBAC authorization-version increments;
- team-member invitation and human acceptance;
- privileged-access maker-checker;
- Admin API surface;
- v1.4 schema extension plan;
- DI authorization alignment;
- deployed Security -> DI E2E.

The old unavailable `SECURITY_OPENAPI_v1.3.yaml` still gates the older v1.3 lifecycle routes, but it no longer
blocks the new v1.4 Admin Control Plane because v1.4 explicitly versions that new contract.

## 4. Current blockers that still remain

- **Tenant activation:** complete SEC-032 prerequisite catalogue remains incomplete. Keep activation disabled.
- **Persistent idempotency:** approved cross-replica persistence model remains missing.
- **Device BLOCKED vs REVOKED:** both are non-ACTIVE, but their separate mutation semantics remain unfrozen.
- **Legacy lifecycle routes:** still require the unavailable v1.3 OpenAPI.
- **Clerk live orchestration:** Security-side onboarding state exists; live provider API orchestration is later.
- **SYSTEM/SERVICE_INTEGRATION issuance:** remains Phase 6 after the Admin Control Plane priority.

The old Admin permission and RBAC `authorization_version` blockers are resolved by v1.4 and MUST NOT be treated
as open after reset.

## 5. Current execution pointer

**NOW:** implement Admin Control Plane v1.4.

Start with:

```text
Increment A
  migration 0002_security_admin_control_plane_v1.4.sql
      ↓
  security.* permission catalogue
      ↓
  standard Platform/Tenant Admin roles
      ↓
  module/group/invitation/approval/admin-audit persistence
      ↓
  real Neon validation
```

Then:

```text
Increment B  Platform Super Admin bootstrap/login + direct Tenant creation
Increment C  Module catalogue API + DI permission/template synchronization
Increment D  Groups + effective RBAC
Increment E  Tenant role Admin APIs
Increment F  Team-member invitation + human acceptance
Increment G  Privileged maker-checker
Increment H  Existing policy/location/schedule/device Admin APIs
Increment I  DI authorization alignment
Increment J  Deployed Security -> DI E2E
```

Do **not** switch the primary workstream to Phase 6 until this practical Admin Control Plane is implemented and
validated.

## 6. DI recovery for cross-module work

Before DI alignment work, inspect current DI `dev` and read:

1. `DI_MASTER_REFERENCE.md`;
2. `backend/src/verigence/di/auth/permissions.py`;
3. `backend/src/verigence/di/auth/verifier.py`;
4. `backend/src/verigence/di/auth/dependencies.py`;
5. applicable DI OpenAPI/RBAC source when available.

Important current findings already captured in v1.4:

- DI already verifies Security JWT/JWKS;
- DI already treats `permissions[]` as authoritative;
- DI currently defines 28 canonical `di.*` permissions;
- DI actor type `SERVICE` must align to Security `SERVICE_INTEGRATION`;
- DI must fail closed on unknown actor types;
- Tenant-scoped SYSTEM handling must align with Security;
- DI Tenant path naming/permission coverage must be normalized and tested.

## 7. Promotion discipline

```text
feature/*
   ↓ real Neon tests + Security CI
  dev
   ↓ exact-commit Security CI
immutable GHCR image
   ↓
Railway DEV
   ↓ readiness + liveness + correlation
```

Cross-repository DI changes follow DI's own feature/PR/CI discipline and must be validated before deployed E2E.

## 8. Context-reset warning

Do not restart from Phase 1, Phase 4, or Phase 6 after a reset.

The primary execution position is **Security Admin Control Plane v1.4, Increment A** until the tracker says
otherwise.
