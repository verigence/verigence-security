# Verigence Security — Admin Control Plane Increment G Validation

**Increment:** G — privileged-access maker-checker  
**Status:** UNDER VALIDATION  
**Authority:** `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`, section 16 and section 17.8  
**Active identity model:** Platform-global USER onboarding v1.4.2+; Tenant access is authorization assignment, not identity onboarding.

## Scope

Increment G enforces maker-checker on assignment of these reserved Tenant roles:

```text
tenant.owner
tenant.admin
tenant.rbac_admin
tenant.access_admin
tenant.security_policy_admin
tenant.security_approver
```

`tenant.user_admin`, `tenant.auditor`, and Tenant-defined business roles remain directly assignable when the caller has `security.role.assign`.

## Active flow

```text
Maker with security.role.assign
  -> PUT /security/v1/admin/tenants/{tenantId}/members/{userId}/roles/{roleId}
  -> if ordinary role: ACTIVE assignment is materialized immediately
  -> if privileged role: PENDING privileged_access_request is created
  -> no ACTIVE user_role_assignment exists yet

Independent checker with security.privileged_access.approve
  -> GET /security/v1/admin/tenants/{tenantId}/privileged-access-requests
  -> POST .../{requestId}/approve OR /reject
  -> requester cannot decide their own request
  -> subject cannot decide their own request

APPROVE
  -> request=APPROVED
  -> ACTIVE user_role_assignment materialized
  -> effective Tenant authorization version incremented

REJECT
  -> request=REJECTED
  -> no privileged role assignment materialized
```

## Global USER correction

The original v1.4 design described new-member Tenant invitation acceptance. Tenant-scoped identity onboarding was later superseded by the global once-per-person USER model. Increment G therefore applies maker-checker to the active Tenant authorization assignment endpoint. Historical `source_invitation_id` remains supported by the existing persistence contract but is not required for current role assignment.

## Persistence

The existing `security.privileged_access_requests` table from migration `0002` remains authoritative.

Additive migration `0008_privileged_access_maker_checker_v1.4.7.sql` adds:

- one-PENDING-request uniqueness for `(tenant_id, subject_user_id, role_id)`;
- Tenant/status/time lookup indexing.

## Acceptance gates

Real PostgreSQL validation must prove:

1. privileged role request creates `PENDING` request and no ACTIVE role assignment;
2. duplicate PENDING request is idempotently suppressed;
3. requester cannot approve/reject their own request;
4. subject cannot approve/reject their own request;
5. checker must be separately authorized with `security.privileged_access.approve` at the API gate;
6. independent approval creates exactly one ACTIVE role assignment;
7. assignment preserves the maker as `assigned_by_user_id` and records the checker on the request;
8. approval increments the subject's Tenant authorization version;
9. rejection creates no role assignment;
10. non-privileged `tenant.user_admin` remains directly assignable;
11. all historical Security/Clerk/global USER/Super Admin regressions remain green;
12. exact-head Security CI and Neon/PostgreSQL are green before merge;
13. post-merge exact-commit Security CI and Railway readiness/liveness/correlation are green.

The deferred live Clerk onboarding `/complete` proof is not an Increment G dependency by explicit project direction; it remains recorded as a separate v1.4.6 validation item.
