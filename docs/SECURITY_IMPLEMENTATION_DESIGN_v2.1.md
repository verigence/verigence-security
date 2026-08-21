# Verigence Security — Phase-1 Implementation Design UC02 Revision

**Version:** 2.1  
**Status:** DESIGN READY FOR UC02 CONTRACT IMPLEMENTATION  
**Date:** 2026-08-21  
**Repository:** `verigence/verigence-security`  
**Target branch:** `dev`  
**Base implementation design:** `docs/SECURITY_IMPLEMENTATION_DESIGN_v2.0.md` dated 2026-08-19  
**Authoritative UC02 solution revision:** `docs/SECURITY_SOLUTION_DESIGN_v2.1.md`

> This document is an implementation-design delta only. It does not change application code, database DDL or migrations. Security v2.0 implementation design remains authoritative except where this document explicitly supersedes it for UC02 Project Onboarding & Administration.

---

## 1. Scope

This revision defines the Security work needed by UC02 and nothing beyond it:

1. server-generated Tenant Code for Project creation;
2. human-administrator token propagation for Audit Core -> Security admin calls;
3. existing operating-role assignment reused for Project role association;
4. correction of the old Dealer/Outlet single-scope assumption;
5. Phase-1 SuperAdmin Tenant hard delete for Project rollback;
6. Security-side tests for the above.

No new USER-membership entity, Dealer/Outlet table, Product Master model or Web BFF is introduced in Security.

---

## 2. Administrative request authentication

### 2.1 Incoming actor

For UC02 Security administrative requests proxied/orchestrated by Audit Core:

```text
Authorization: Bearer <Security-issued human access JWT>
X-Correlation-ID: <forwarded/generated correlation id>
```

The token SHALL be the same human token that initiated the browser request.

Security's existing human administrative dependency/policy is used:

```text
validate Security human JWT
 -> resolve global USER
 -> require USER ACTIVE
 -> require actor_type USER
 -> resolve current admin classification/scope
 -> authorize operation
```

The proxying network hop through Audit Core does not change the actor.

### 2.2 Explicit machine denial

A valid `ServiceIntegration` JWT MUST be rejected from the UC02 Security administrative operations, including:

- create Tenant;
- update Tenant;
- activate Tenant;
- hard-delete Tenant;
- set/remove operating role.

`ServiceIntegration` remains valid for the existing machine paths such as `/authorization/check` and normal module integration where designed.

### 2.3 Audit actor

Security audit events SHALL record the global USER resolved from the human JWT as `actor`, not the Audit Core service principal.

Audit Core may forward correlation/idempotency context, but it cannot supply an actor ID that overrides the authenticated human subject.

---

## 3. Tenant create contract

### 3.1 External request

The UC02 caller does not supply `tenantCode`.

Logical request:

```http
POST /security/v1/platform/tenants
Authorization: Bearer <human SuperAdmin JWT>
Content-Type: application/json
```

```json
{
  "tenantName": "Hyundai West Audit Project"
}
```

If the retained Security Tenant create contract contains other **existing Security-owned optional fields**, those fields may remain only where they already exist and do not conflict with UC02. This revision does not invent additional Security-owned Project metadata.

Project OEM, Product Category, dates, timezone and geography remain Audit Core fields, not Security Tenant fields.

### 3.2 Internal Tenant Code generation

Security generates a stable internal Tenant Code before insert.

Required properties:

- generated server-side;
- unique under the existing Tenant uniqueness constraint;
- deterministic collision handling within the create transaction/retry path;
- immutable as normal business input after creation;
- not derived as an authorization key;
- not required to be meaningful to a SuperAdmin.

The exact formatting algorithm is deliberately not frozen here because the existing repository convention/validation must be reused rather than replaced with an invented format. The implementation must document and test the chosen existing-compatible convention before code review.

### 3.3 Idempotent Project-creation orchestration

Audit Core may retry the outer Project create operation. Security Tenant creation therefore needs retry-safe semantics at the orchestration boundary.

Security SHALL NOT create multiple Tenants merely because the browser/Audit Core retried after a timeout.

The concrete idempotency mechanism shall follow Security's existing request/change-record patterns where available. If the current Tenant API does not yet carry an idempotency header, the Security API/OpenAPI implementation work must add one rather than relying on Tenant Name uniqueness as the idempotency mechanism.

No exact new header name is invented here beyond the platform's already-used `Idempotency-Key` convention.

### 3.4 Create result

The result must expose at minimum:

```text
tenantId        canonical generated UUID
internal tenantCode
Tenant name
Tenant lifecycle status
```

The outer Web UI may hide `tenantCode`.

New Project/Tenant lifecycle remains `CONFIGURING` until explicit activation.

---

## 4. Tenant read/update/activate

### 4.1 Existing APIs retained

```text
GET   /security/v1/platform/tenants
GET   /security/v1/platform/tenants/{tenantId}
PATCH /security/v1/platform/tenants/{tenantId}
POST  /security/v1/platform/tenants/{tenantId}/activate
```

### 4.2 Project business metadata

Security SHALL NOT be expanded to hold Audit Core Project fields only because the UC02 form contains them.

Security update remains limited to Security-owned Tenant metadata/lifecycle fields already approved by Security design.

Audit Core owns Project Name/business metadata presentation and its own Project projection. Where a shared display name must be kept consistent, the orchestrator must update the owning fields through their existing owning-module APIs and report partial failure accurately.

### 4.3 Activation

Activation remains Security-owned lifecycle administration.

Audit Core performs Project Readiness first. Only after all blocking checks pass does Audit Core invoke Security activation using the same SuperAdmin human JWT.

Security is not required to duplicate Audit Core Dealer/Outlet/master readiness logic.

---

## 5. Operating-role assignment for UC02

### 5.1 Reuse unchanged role model

Use existing target APIs:

```text
PUT    /security/v1/tenants/{tenantId}/users/{userId}/operating-role
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

No independent `project_membership` write is added.

Security continues to enforce:

- USER must be eligible/ACTIVE under the existing assignment rules;
- one ACTIVE operating role per `(user_id, tenant_id)`;
- exactly one ACTIVE PM per Tenant;
- administrative/operating persona exclusivity;
- role-aligned Group membership follows the operating role.

### 5.2 Role Mapping orchestration

Audit Core's UC02 Role Mapping operation combines:

```text
Security: operating role
+
Audit Core: Dealer / Dealer Outlet business scope
```

Security does not accept Dealer or Outlet IDs in the operating-role payload.

If the Audit Core business-scope write fails after the Security role succeeds, the outer operation is not reported as complete. Audit Core owns reconciliation/compensation of that composite operation.

### 5.3 Remove Employee from Project

For Phase 1, removing a persisted Employee/Project association means removing the Tenant operating role plus the relevant Audit Core business assignment.

Security role removal:

- removes Tenant authorization/group membership;
- does not change the global USER status;
- does not delete the USER;
- does not remove that USER's roles in other Tenants.

---

## 6. Dealer / Dealer Outlet boundary

Security implementation SHALL remove the UC02 dependency on the old design assumption that Dealer and Outlet are one assignment concept.

No Security schema is added for either entity.

Security's runtime decision remains functional permission only.

Audit Core receives the role context from Security authorization where useful and independently enforces:

```text
PC        -> Outlet scope
TL        -> Dealer scope
PM        -> Project scope
CRM       -> Dealer or Project scope
Executive -> Project scope
```

The UC02 readiness rule requiring a PC for every ACTIVE Outlet is an Audit Core rule and requires no Security persistence change.

---

## 7. Tenant hard-delete implementation contract

### 7.1 API

Add to the Security target administrative API:

```http
DELETE /security/v1/platform/tenants/{tenantId}
Authorization: Bearer <human SuperAdmin JWT>
```

Recommended retry context uses the existing platform correlation/idempotency conventions.

### 7.2 Preconditions

Security verifies only Security-owned preconditions:

1. Tenant identifier is valid;
2. Tenant exists, or prior successful deletion can be recognized as an idempotent terminal result according to final API response semantics;
3. caller is the one ACTIVE Phase-1 SuperAdmin;
4. actor is human, not `ServiceIntegration`.

Security does not query DI/Audit Core private databases to prove their purge. Audit Core owns cross-module orchestration and calls Security last.

### 7.3 Security delete graph

The implementation design shall enumerate every Tenant-scoped Security FK/table before code is written. Based on the approved v2.0 target model, the delete must remove/end Tenant-scoped live state including:

- `user_tenant_operating_roles` for the Tenant;
- `tenant_role_permissions` for the Tenant;
- Tenant-scoped `TenantAdmin` assignments;
- persisted role-aligned Group metadata/membership if such tables are used;
- TestTenant singleton/config link if and only if the deleted Tenant is the configured TestTenant and deletion is otherwise permitted by the environment/bootstrap rules;
- legacy Tenant-scoped authorization rows that still have FK dependencies and would otherwise prevent deletion;
- the Tenant row itself.

Global data not deleted:

- `security.users`;
- Clerk `external_identities` for those global USERs;
- operating roles for other Tenants;
- ModuleAdmin/SuperAdmin assignments unrelated to the deleted Tenant;
- module/permission catalogue;
- Security audit records required by Security's retention model.

No implementation may rely on a broad database `CASCADE` without an explicitly reviewed delete graph proving what would be deleted.

### 7.4 Transaction and retry behaviour

Security-owned relational cleanup and Tenant-row deletion should complete atomically where the existing DB relationships permit it.

If a non-transactional dependency exists inside Security, the operation must expose failure rather than report success early.

Repeated request after confirmed successful deletion must not recreate or double-apply anything.

### 7.5 Audit record

Security records:

- operation/correlation ID;
- human SuperAdmin actor USER ID;
- target Tenant ID and safe Tenant metadata;
- requested time;
- completion/failure time;
- outcome;
- safe failure summary when applicable.

Do not store bearer tokens.

---

## 8. Cross-module whole-Project rollback contract

Security participates only in its owning final step.

Expected orchestrator sequence:

```text
Audit Core deletion operation
  1. authorize SuperAdmin
  2. freeze/reject new Project writes
  3. DI purge and verify DI zero state
  4. Audit Core delete and verify Audit Core zero state
  5. DELETE Security Tenant using same human JWT
  6. verify Security Tenant no longer exists
  7. report overall completion
```

If step 5 fails, the overall Project delete remains incomplete and retryable. Audit Core must not report the Project fully deleted.

Security does not create a new cross-module saga table; the saga belongs to Audit Core.

---

## 9. Security API contract changes to freeze before code

| Area | v2.0/current target | UC02 v2.1 target |
|---|---|---|
| Tenant create | caller supplies Tenant Code in current implementation contract | server-generated Tenant Code; caller supplies no code |
| Tenant lifecycle | create/read/update/activate | retain |
| Tenant hard delete | absent | add SuperAdmin human-admin DELETE |
| Employee Project membership | operating role only | retain; no new membership entity |
| Dealer/Outlet IDs | not Security-owned | retain; explicitly support separate Audit Core Dealer and Outlet scope |
| Admin proxy actor | admin endpoints human-only | forwarded original Security human JWT accepted; `ServiceIntegration` denied |

---

## 10. Required tests before Security UC02 completion

### Tenant creation

- no `tenantCode` field accepted as authoritative caller input;
- generated code satisfies existing format/length constraints;
- generated code is unique;
- timeout/retry does not create duplicate Tenant under the final idempotency contract;
- Tenant starts in `CONFIGURING`;
- caller is recorded as human SuperAdmin;
- valid ServiceIntegration token is denied.

### Role Mapping support

- existing set/replace role semantics still pass;
- exactly one PM per Tenant still passes;
- role remove affects only target Tenant;
- role remove preserves global USER;
- no Dealer/Outlet identifier is required or persisted by Security.

### Activation

- forwarded SuperAdmin human JWT is accepted;
- ServiceIntegration is rejected;
- Tenant lifecycle changes correctly;
- correlation/audit actor is retained.

### Tenant hard delete

- no token -> deny;
- ordinary operating USER -> deny;
- TenantAdmin -> deny Phase-1 hard delete;
- ModuleAdmin -> deny;
- ServiceIntegration -> deny;
- SuperAdmin -> allowed;
- global USER rows preserved;
- other-Tenant role assignments preserved;
- Tenant role bundles/role assignments for deleted Tenant removed;
- duplicate retry after success is safe according to frozen response semantics;
- failure cannot be reported as success;
- Security audit evidence remains after Tenant row removal.

---

## 11. No-code-change boundary

This document deliberately does not:

- alter Python code;
- add or edit SQL migrations;
- edit OpenAPI/YAML;
- choose a new Tenant Code format where the repository already has a convention;
- invent new Security permissions;
- change USER deletion semantics;
- add Dealer/Outlet data to Security.

Those implementation artifacts may be changed only after the design/API review is explicitly approved.