# Verigence Security — Admin Control Plane Increment H Validation

**Status:** IMPLEMENTATION IN PROGRESS  
**Repository:** `verigence/verigence-security`  
**Branch:** `feature/admin-policy-access-h`  
**Base deployed commit:** `b37322c3098f964fda20aae8d7b40f2f26fa6afc`  
**Date:** 2026-08-14

## 1. Increment G handoff

Increment G privileged-access maker-checker is merged and deployed on the base commit above.

Post-merge evidence:

```text
Security CI #193:           PASS
Railway DEV #50:            PASS
Immutable image deployment: PASS
Readiness:                  PASS
Liveness:                   PASS
Correlation ID:             PASS
```

The final live Clerk `/complete -> USER=PENDING` onboarding E2E remains deferred by explicit project direction and is not a blocker for Increment H.

## 2. Governing H scope

`SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` Increment H requires exposure of the already-validated internal administration services for:

- Tenant Security Policy;
- Security Retention Policy;
- Tenant locations;
- schedules/windows;
- explicit USER location/schedule assignment;
- device read/approval.

Device block/revoke mutations remain disabled until their business semantics are frozen.

`SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md` is an approved extension to the Admin Control Plane and is therefore part of the H workstream as a coordinated H1 track:

- persisted Security Control Registry definitions/settings/overrides;
- Platform security-control administration APIs;
- deterministic effective-control resolution;
- runtime wiring for configurable contextual controls.

H is executed as:

```text
H1 Security Control Registry/runtime switches
H2 Existing policy/access/device Admin APIs
```

## 3. Newer global USER model takes precedence over historical membership prerequisites

The active Platform-global USER model intentionally removed `tenant_memberships` as a prerequisite for human Tenant authorization. The same ACTIVE global USER may receive Tenant-scoped roles/groups/locations/schedules across multiple Tenants without another identity onboarding event or mandatory Tenant membership row.

Increment H MUST NOT reintroduce a Tenant membership requirement through older internal services.

In particular:

- Tenant Admin API authorization uses the current Tenant RBAC gate: ACTIVE Tenant + ACTIVE global USER + ACTIVE principal + effective Tenant permission;
- explicit USER location/schedule assignment validates the global USER and same-Tenant location/schedule resources rather than requiring a membership row;
- device read/approval MUST NOT fail solely because `security.tenant_memberships` is absent;
- the historical `core.tenant_membership_validation` wording in `SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md` cannot be used to restore a removed authorization prerequisite.

The registry may expose legacy definition metadata only after the governing model is reconciled; runtime authorization remains the current global USER/Tenant RBAC model.

## 4. H2 API exposure contract

All Tenant routes use:

```text
/security/v1/admin/tenants/{tenantId}/...
```

and the normal Tenant USER Security token. Platform Admin tokens are not accepted on these Tenant Admin routes.

### Policy

```text
GET /security/v1/admin/tenants/{tenantId}/security-policy
PUT /security/v1/admin/tenants/{tenantId}/security-policy
GET /security/v1/admin/tenants/{tenantId}/retention-policy
PUT /security/v1/admin/tenants/{tenantId}/retention-policy
```

Permissions:

```text
security.policy.read
security.policy.update
security.retention.read
security.retention.update
```

### Locations

```text
GET  /security/v1/admin/tenants/{tenantId}/locations
POST /security/v1/admin/tenants/{tenantId}/locations
GET  /security/v1/admin/tenants/{tenantId}/locations/{locationId}
PUT  /security/v1/admin/tenants/{tenantId}/locations/{locationId}
```

Permissions:

```text
security.location.read
security.location.create
security.location.update
```

### Schedules/windows

```text
GET  /security/v1/admin/tenants/{tenantId}/schedules
POST /security/v1/admin/tenants/{tenantId}/schedules
GET  /security/v1/admin/tenants/{tenantId}/schedules/{scheduleId}
PUT  /security/v1/admin/tenants/{tenantId}/schedules/{scheduleId}
```

A schedule representation includes its windows. Mutations materialize/upsert the supplied schedule/window IDs without inventing implicit deletion semantics for omitted windows.

Permissions:

```text
security.schedule.read
security.schedule.create
security.schedule.update
```

### Explicit USER location/schedule assignments

```text
GET    /security/v1/admin/tenants/{tenantId}/members/{userId}/location-assignments
PUT    /security/v1/admin/tenants/{tenantId}/members/{userId}/location-assignments/{assignmentId}
DELETE /security/v1/admin/tenants/{tenantId}/members/{userId}/location-assignments/{assignmentId}
```

Permission:

```text
security.location.assign
```

Assignments remain explicit USER context. Groups cannot grant locations/schedules.

### Devices

```text
GET  /security/v1/admin/tenants/{tenantId}/devices
GET  /security/v1/admin/tenants/{tenantId}/devices/{deviceId}
POST /security/v1/admin/tenants/{tenantId}/devices/{deviceId}/approve
```

Permissions:

```text
security.device.read
security.device.approve
```

No block/revoke Admin route is enabled in H.

## 5. H2 acceptance

Automated PostgreSQL tests must prove:

1. every route is Tenant-scoped and permission-gated;
2. cross-Tenant resource IDs fail closed;
3. policy/retention mutations persist and create structured Admin audit evidence;
4. location/schedule mutations use existing validated tables and create structured Admin audit evidence;
5. explicit location/schedule assignment works for an ACTIVE global USER without a `tenant_memberships` row;
6. group/RBAC changes do not grant a location/schedule;
7. device reads are Tenant-isolated;
8. pending device approval works without restoring a Tenant membership prerequisite;
9. device limit still uses the Tenant Security Policy when device-limit enforcement is active;
10. no block/revoke route exists.

## 6. H1 Control Registry acceptance

Implementation follows `SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md` except that no historical Tenant-membership authorization prerequisite may be restored.

Real Neon and deployed DEV must prove:

- seeded defaults preserve currently active contextual enforcement;
- Platform setting and supported Tenant override precedence is deterministic;
- parent control short-circuit works;
- non-configurable controls reject mutation;
- changes require reason and structured audit evidence;
- RBAC and Tenant isolation remain mandatory while contextual controls are disabled;
- re-enabling a control evaluates existing persisted policy/device/location/schedule state.

## 7. Promotion discipline

```text
feature/admin-policy-access-h
  -> Security CI
  -> real Neon/PostgreSQL H acceptance
  -> PR review/merge to dev
  -> exact-commit Security CI
  -> immutable Railway DEV deployment
  -> readiness/liveness/correlation
```
