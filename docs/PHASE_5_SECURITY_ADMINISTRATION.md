# Phase 5 — Security Administration Foundation

**Status:** PARTIAL — Increments 1–3 validated on Neon DEV  
**Approved baseline:** Security Solution v1.3  
**Latest Neon validation run:** `31680129517`

## Objective

Build Security administration from the approved persistence model without inventing public API shapes or endpoint-level `security.*` permission keys that are not frozen by the approved design.

## Increment 1 — Tenant Security Policy and Retention Policy administration

Implemented internal administration for:

- `security.tenant_security_policies`;
- `security.security_retention_policies`.

Every approved Security threshold/TTL and every retention duration is supplied explicitly. No numeric Security default is introduced. An ACTIVE policy written through Phase 5 is consumed unchanged by the existing runtime `SecurityRepository.get_tenant_policy()` path.

Initial Neon run `31678680842`: **SUCCESS**.

## Increment 2 — Tenant location and schedule administration

Implemented internal administration for:

- `security.tenant_locations`;
- `security.access_schedules`;
- `security.access_schedule_windows`.

Location geo/radius/timezone/address/status and normal/overnight schedule windows are stored exactly as supplied. Existing runtime schedule readers consume the administered rows directly. No implicit schedule-window deletion/replacement semantics are invented.

Neon run `31679363993`: **SUCCESS — 6/6 tests**.

## Increment 3 — Tenant membership, employee-location and RBAC administration

Implemented internal administration for existing USER principals across:

- `security.tenant_memberships`;
- `security.permissions`;
- `security.roles`;
- `security.role_permissions`;
- `security.user_role_assignments`;
- `security.user_location_assignments`.

The increment adds:

- `MembershipAdminRepository` for Tenant/user membership configuration;
- `RbacAdminRepository` for canonical permission catalogue entries, Tenant roles, role-permission grants and user-role assignments;
- `UserLocationAdminRepository` for employee-to-approved-location/schedule assignment;
- `TenantAuthorizationConfigurationService` coordinating the internal administration transactions;
- canonical dot-notation validation for supplied permission keys;
- no automatic `authorization_version` mutation policy beyond the explicitly supplied value, because that mutation policy is not frozen by the active approved sources.

The runtime acceptance test uses the explicitly approved example permission `di.document.upload`; no new production permission key is invented.

## Neon validation

Workflow: `.github/workflows/phase5-neon-admin.yml`  
Latest run: `31680129517`  
Result: **SUCCESS — 7/7 Phase 5 PostgreSQL tests passed**.

The Increment 3 acceptance test proves that records created by the administration services are immediately consumed by the existing production runtime:

1. `SecurityRepository.get_user_context()` resolves the administered ACTIVE Tenant membership and authorization version.
2. `SecurityRepository.assigned_locations()` resolves the administered employee location and its schedule.
3. `SecurityRepository.effective_user_permissions()` resolves the administered Tenant role and `di.document.upload` grant.

There is no separate Phase 5 authorization-read model.

## Deliberately not implemented yet

- public administration routes;
- endpoint-level administrator permission checks;
- Tenant activation-readiness result model/service;
- Tenant activation mutation;
- external identity / Clerk onboarding administration;
- implicit removal/replacement semantics for assignments or schedule windows;
- automatic `authorization_version` bump rules not explicitly frozen by approved design.

The exact public admin permission catalogue remains blocked. Phase 5 therefore continues through deterministic internal services first.

## Next safe increment

Implement SEC-032 Tenant activation-readiness as an internal query that reports only prerequisites deterministically supported by approved sources/schema, then add the activation state transition only when every required prerequisite is explicitly represented and green.
