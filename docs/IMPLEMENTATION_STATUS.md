# Verigence Security Implementation Status — Reviewed Baseline + Promoted Increments

This implementation remains grounded in Security v1.3 plus explicitly versioned extensions and clarifications.

The new Security Admin Control Plane authority is:

```text
docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md
```

It does not silently supersede v1.3 lifecycle artifacts. It explicitly defines the new administration/control-plane
scope.

Detailed execution/evidence is maintained in `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.

## Core baseline

The promoted implementation includes:

- FastAPI/Railway service foundation;
- environment safety controls;
- correlation-ID middleware;
- Clerk USER identity verification adapter and DEV mock identity boundary;
- Security Principal USER validation;
- Security Access JWT/JWKS baseline;
- canonical permissions;
- USER geo/time/network/RBAC evaluation;
- Neon/PostgreSQL foundation;
- USER access-session lifecycle;
- evidence persistence;
- health/live and fail-closed readiness;
- exact approved v1.3 PostgreSQL migration source and error catalogue.

## Validated phase milestones

- **Phase 1 CI — DONE.**
- **Phase 2 Neon DEV — DONE.**
- **Phase 3 Railway DEV — DONE.**
- **Phase 4 internal USER device/session lifecycle — substantially DONE.**
- **Phase 5 deterministic internal Security administration foundation — substantially DONE.**
- **Admin Control Plane v1.4 design — READY FOR IMPLEMENTATION.**

## Phase 4 internal runtime status

Implemented/validated:

- PENDING device enrollment persistence and approval transition;
- concurrent Tenant active-device-limit enforcement;
- one ACTIVE USER session invariant;
- USER session revoke;
- mandatory fresh geo on refresh;
- complete refresh policy re-evaluation;
- approved refresh location movement;
- session maximum-duration preservation;
- canonical device→session lock order;
- successful/denied access-context evidence;
- non-ACTIVE device refresh/new-issuance rejection.

Latest accumulated Phase 4 Neon suite: `31675733002` — **12/12 PASS**.  
Security CI `31675854749` and Railway `31675854751` — PASS.

Older v1.3 lifecycle route shapes still depend on the unavailable v1.3 OpenAPI and are not invented by v1.4.

## Phase 5 internal administration foundation

### Tenant policy and retention administration — DONE

Internal administration exists for:

- `tenant_security_policies`;
- `security_retention_policies`.

### Tenant location and schedule administration — DONE

Internal administration exists for:

- `tenant_locations`;
- `access_schedules`;
- `access_schedule_windows`.

### Tenant membership, employee-location and RBAC administration — DONE

Internal administration exists for:

- `tenant_memberships`;
- canonical `permissions`;
- `roles`;
- `role_permissions`;
- `user_role_assignments`;
- `user_location_assignments`.

Existing runtime authorization readers directly consume these administered records.

### Security-side USER onboarding — DONE internally

Implemented:

- USER `security_principals` persistence;
- `security.users` persistence;
- `external_identities` provider-subject mapping;
- protection against external-identity rebinding;
- protection against retyping a machine principal as USER.

### SEC-032 Tenant activation readiness — PARTIAL / FAIL-CLOSED

Known readiness checks are implemented, but the complete activation prerequisite catalogue remains incomplete.

The Tenant remains `CONFIGURING` and activation remains disabled.

## Latest Phase 5 evidence

- Increment 1 PR #31; Railway `31678834647` — PASS.
- Increment 2 PR #32; Railway `31679593399` — PASS.
- Increment 3 PR #33; Railway `31680433590` — PASS.
- Increment 4 PR #34; Railway `31681204041` — PASS.
- Increment 5 PR #35; Railway `31681687106` — PASS.
- Latest accumulated Phase 5 Neon suite `31681385872` — **11/11 PASS**.

## Admin Control Plane v1.4 — design status

The former Phase 5 public-Admin/API design blocker has been explicitly resolved by a new versioned design rather
than by reconstructing the missing v1.3 OpenAPI.

v1.4 freezes:

- Platform Super Admin bootstrap and Platform Admin authentication;
- direct Platform Admin Tenant creation;
- four standard Platform admin roles;
- eight standard Tenant admin roles;
- exact `security.*` Admin permission catalogue;
- Tenant Groups and Group→Role inheritance;
- no nested Groups;
- explicit USER location/schedule assignments outside Groups;
- module permission catalogue registration;
- module role templates;
- module namespace ownership;
- no automatic Tenant-Role mutation when templates change;
- RBAC `authorization_version` bump rules;
- team-member invitation/human acceptance;
- privileged-access maker-checker;
- Admin API route plan;
- exact logical v1.4 database extension contract;
- structured Admin change audit;
- DI alignment and Security→DI E2E requirements.

The temporary DEV bootstrap password value is deliberately not written to Git or documentation. It is a deployment
secret and must be Argon2id-hashed before persistence.

## Current remaining blockers

The following remain genuinely unresolved and are not solved by v1.4:

- complete SEC-032 activation prerequisite catalogue;
- Tenant activation mutation;
- persistent cross-replica idempotency persistence model;
- device `BLOCKED` versus `REVOKED` business mutation semantics;
- older v1.3 lifecycle route shapes dependent on the missing v1.3 OpenAPI;
- live Clerk invitation/provider orchestration details;
- SYSTEM/SERVICE_INTEGRATION credential/token implementation;
- retention purge/offboarding execution;
- overlapping JWKS rotation;
- WPM catalogue until WPM is reviewed;
- UAT/Production readiness.

The former endpoint-level Admin permission blocker and RBAC authorization-version blocker are resolved by v1.4.

## Current execution direction

The primary implementation workstream is now:

```text
Admin Control Plane v1.4 — Increment A
  migration 0002_security_admin_control_plane_v1.4.sql
      ↓
  standard security.* permissions and Admin roles
      ↓
  module/group/invitation/privileged-approval/admin-audit persistence
      ↓
  real Neon validation
```

Then follow the v1.4 sequence through Platform Super Admin/Tenant creation, DI catalogue synchronization, Groups,
Tenant Role APIs, human onboarding, maker-checker, existing Admin service exposure, DI alignment, and deployed
Security→DI E2E.

Do not switch the primary workstream to Phase 6 until this practical Admin Control Plane is implemented and
validated.
