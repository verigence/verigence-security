# Verigence Security — Phase-1 Implementation Design

**Version:** 2.0  
**Status:** DRAFT FOR IMPLEMENTATION REVIEW  
**Date:** 2026-08-19  
**Repository:** `verigence/verigence-security`  
**Target branch:** `dev`  
**Authoritative architecture:** `docs/SECURITY_SOLUTION_DESIGN_v2.0.md`

> This document is an implementation blueprint only. It does not authorize application-code or migration changes. It translates the approved Security v2.0 solution design into a concrete reuse, data, API, migration and test plan. Where current `dev` implementation conflicts with the approved solution design, the solution design wins. No Audit Core or DI file is changed by this document.

---

## 1. Scope and implementation rules

This implementation design covers only `verigence/verigence-security`.

Audit Core and DI may be read to validate permission catalogues and integration boundaries, but their implementation is outside this change set.

Implementation rules:

1. Reuse current implementation where it cleanly matches the approved v2.0 design.
2. Modify rather than rewrite when existing code provides a safe reusable base.
3. Retire conflicting runtime paths without rewriting historical migrations.
4. Keep historical/deferred tables and code where removal is not required for Phase 1.
5. Do not invent business rules or permission keys.
6. New permission keys, where genuinely required and not already present, must be explicitly approved before coding/migration.
7. Human authentication remains Clerk first-party session JWT only.
8. Security issues JWTs only for machine/service identities in the target Phase-1 model.
9. Human authorization is synchronous and fail-closed.
10. Device/Geo/Schedule/VPN capabilities are retained but deferred from the active Phase-1 human authorization path.

### 1.1 Additional implementation decisions confirmed after solution-design review

The following implementation decisions are confirmed and are treated as binding for this blueprint:

- Device / Geo / Schedule / VPN controls remain in the repository/database but are not active Phase-1 human authorization gates.
- `PENDING -> ACTIVE` and `PENDING -> REJECTED` are SuperAdmin-only actions.
- `ACTIVE -> SUSPENDED` may be initiated by `Executive` and `TenantAdmin` within their existing Tenant scope. The resulting USER status is global, therefore access is denied across all Tenants. SuperAdmin also retains the capability through its all-permissions authority.
- `ServiceIntegration` principals are platform-global, not Tenant-scoped.

---

## 2. Current implementation inventory and disposition

### 2.1 Identity and human authentication

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.users` | Security human USER | Keep global USER; status model changes | **REUSE WITH MODIFICATION** |
| `security.external_identities` | Clerk/DEV_MOCK subject mapping | Keep one Clerk subject -> one global USER | **REUSE AS-IS / MINOR MODIFICATION** |
| `adapters/identity.py::ClerkJwtIdentityProvider` | Local Clerk JWT verification | Keep; align final Clerk key/JWKS configuration and required checks | **REUSE WITH MODIFICATION** |
| `api/dependencies.py::identity_from_token` | Select Clerk/DEV mock identity verifier | Keep for Clerk human resource endpoints; DEV mock remains environment-limited | **REUSE WITH MODIFICATION** |
| `services/clerk_credentials.py` human password brokerage | Security receives human password/TOTP and calls Clerk Backend API | Not part of target human login | **RETIRE FROM ACTIVE HUMAN FLOW** |
| `api/routes/access.py::POST /security/v1/auth/login` | Clerk backend credential auth + Security human token issuance | Remove from active target human flow | **RETIRE FROM ACTIVE HUMAN FLOW** |
| `services/platform_admin_token.py` | Security-issued human Platform Admin JWT | Human admins use Clerk JWT instead | **RETIRE FROM ACTIVE HUMAN FLOW** |
| `api/routes/platform_admin.py::/auth/login` | Clerk credential auth + Security Platform Admin JWT | Replace with Clerk JWT resource authentication | **RETIRE/REWIRE** |

### 2.2 Global USER onboarding and lifecycle

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `platform_user_onboarding_settings` | Platform-global onboarding key | Retain | **REUSE** |
| `platform_user_onboarding_requests` | Global onboarding workflow | Retain; align status transitions and first-party Clerk flow | **REUSE WITH MODIFICATION** |
| `GlobalUserOnboardingService` | Global USER lifecycle/onboarding | Strong base; modify credential flow, REJECTED, deletion, transition authority | **REUSE WITH MODIFICATION** |
| `Phase1SelfOnboardingService` / password+OTP route facade | Security-mediated Clerk signup | Replace with Clerk-owned signup + authenticated bind | **RETIRE/REPLACE ACTIVE FLOW** |
| `GET /platform/users` | Global USER listing | Retain and extend filtering/search/pagination/detail | **REUSE WITH MODIFICATION** |
| `PATCH /platform/users/{id}/status` current lifecycle | ACTIVE/SUSPENDED/DISABLED/EXITED | Replace with approved PENDING/REJECTED/ACTIVE/SUSPENDED/DISABLED transition policy | **REUSE WITH MODIFICATION** |
| Current `EXITED` status | Terminal lifecycle state | Not in target Phase-1 canonical status set | **RETAIN HISTORICALLY; RETIRE FROM NEW FLOW** |

### 2.3 Tenant and permission catalogue

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.tenants` | Tenant source of truth | Retain | **REUSE** |
| `PlatformTenantService` and Tenant CRUD routes | Platform Tenant lifecycle | Retain; switch human auth dependency to Clerk + in-process Security AuthZ | **REUSE WITH MODIFICATION** |
| `security.modules` | Registered module catalogue | Retain | **REUSE** |
| `security.permissions` | Canonical permission registry | Retain | **REUSE** |
| `ModuleCatalogService` | Register/update module permissions/templates | Retain | **REUSE WITH MODIFICATION** |
| `GET /platform/modules` and `GET /platform/modules/{module}` | Module discovery | Retain | **REUSE** |
| Missing explicit `GET .../{module}/permissions` | Permission discovery | Add thin explicit resource using current module catalogue data | **NEW API OVER EXISTING DATA** |
| `module_role_templates` | Module role-template source material | Keep as source/default material; no Tenant role identity creation | **REUSE WITH MODIFICATION** |

### 2.4 Roles and Groups

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.roles` | Tenant-created role objects | No longer authoritative role identity | **RETIRE FROM TARGET ACTIVE MODEL** |
| `security.role_permissions` | Tenant role-ID permission mapping | Replace with `(tenant_id, role_key, permission_key)` | **REPLACE ACTIVE MODEL** |
| `security.user_role_assignments` | Additive user-to-Tenant-role assignments | Replace with exactly one operating role per USER/Tenant | **REPLACE ACTIVE MODEL** |
| `TenantRbacAdminService.create_role` | Arbitrary Tenant role creation | Not allowed for fixed Phase-1 operating roles | **RETIRE ACTIVE API** |
| `effective_user_permissions()` | Union direct roles + Group-derived roles + platform roles | Replace with classification-aware single-role/admin/test resolver | **REWRITE CORE QUERY/LOGIC** |
| `security.groups` | Arbitrary Tenant Groups | Can retain metadata only if constrained to system role-aligned Groups | **REUSE WITH MAJOR SIMPLIFICATION** |
| `group_memberships` | Independent Group membership | Operating-role assignment becomes authority; persisted membership optional | **REUSE ONLY IF DERIVED/SYNCHRONIZED** |
| `group_role_assignments` | Group can add role(s) | Conflicts with target | **RETIRE FROM ACTIVE AUTHORIZATION** |
| Group create/update/member/role mutation APIs | Arbitrary Group administration | Replace by read-only role-aligned Group APIs | **RETIRE/REPLACE** |

### 2.5 Platform/admin roles

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `platform_roles` | Platform role catalogue | Reuse only where it aligns to target admin classifications; no human JWT dependency | **REUSE WITH MODIFICATION** |
| `platform_user_role_assignments` | Platform role assignment | Useful base for SuperAdmin; target TenantAdmin/ModuleAdmin need scoped model | **REUSE PARTIALLY** |
| `initial_super_admin.py` | One-time exact Clerk subject provisioning | Strongly aligned to one Phase-1 SuperAdmin | **REUSE WITH MODIFICATION** |
| `provision_initial_super_admin.py` | Operator provisioning entrypoint | Retain; requires full exact Clerk subject at deployment | **REUSE** |
| `0005_super_admin_full_authority.sql` trigger | Gives SuperAdmin every ACTIVE permission | Retain invariant; it already applies to all permissions registered in `security.permissions`, including module permissions | **REUSE STRONGLY** |
| Current `platform.security_admin`, `platform.module_catalog_admin`, `platform.auditor` | Legacy/current platform roles | Not part of confirmed Phase-1 human role taxonomy unless separately retained for compatibility | **RETAIN HISTORICALLY / REMOVE FROM TARGET ASSIGNMENT FLOW** |

### 2.6 Machine / ServiceIntegration

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.security_principals` with `SERVICE_INTEGRATION` | Machine principal base | Retain | **REUSE** |
| `security.service_integrations` | Service integration identity metadata | Retain as canonical service identity table | **REUSE** |
| `security.principal_credentials` | Client ID + hashed secret + lifecycle | Retain | **REUSE** |
| `principal_tenant_scopes` | Tenant-scoped machine scope | Does not fit platform-global ServiceIntegration | **RETIRE FROM TARGET SERVICE AUTHZ** |
| `principal_permission_grants` | Tenant-scoped machine permissions | Does not fit platform-global ServiceIntegration | **RETIRE FROM TARGET SERVICE AUTHZ** |
| `/oauth/token` client_credentials flow | Machine token issuance | Strong reusable implementation base; semantics must become platform-global and audience-aware | **REUSE WITH MODIFICATION** |
| `/oauth/token` token-exchange grant | USER token delegation | Not required Phase 1 | **RETIRE/DEFER** |
| `TokenService` RSA signing/JWKS | Security access JWTs | Retain signing/JWKS; split target machine claim model from retired human claim shape | **REUSE WITH MODIFICATION** |
| `access_sessions` machine rows | Tenant-scoped service sessions | Do not use as target platform-global machine authorization prerequisite | **RETAIN HISTORICALLY / DEFER** |

### 2.7 Device / Geo / Schedule / VPN

Current implementation has substantial capability around:

- `registered_devices`;
- `tenant_locations`;
- `user_location_assignments`;
- access schedules/windows/overrides;
- `tenant_security_policies`;
- network/VPN risk adapters;
- access sessions and geolocation validation.

**Confirmed Phase-1 implementation decision:** keep these tables, code and administration surfaces, but do not invoke them as required checks for the new Clerk-JWT + live-Security-authorization human path.

Classification: **DEFER FROM ACTIVE PHASE-1 HUMAN AUTHORIZATION; DO NOT DELETE**.

---

## 3. Target runtime component model

### 3.1 Human request to Security

```text
Web/Mobile
   |
   | Clerk session JWT
   v
Security API
   |
   +-- locally validate Clerk JWT
   +-- Clerk sub -> global USER
   +-- USER status check
   +-- in-process authorization policy
   +-- execute Security operation
```

Security does not call its own `/authorization/check` endpoint.

### 3.2 Human request to Audit Core or DI

```text
Human
   |
   | Clerk session JWT
   v
Audit Core / DI
   |
   +-- validate Clerk JWT locally
   +-- extract trusted Clerk subject
   |
   | ServiceIntegration JWT of calling backend
   v
Security /authorization/check
   |
   +-- validate backend service token
   +-- resolve Clerk subject -> USER
   +-- USER must be ACTIVE
   +-- resolve Tenant/admin/test authorization
   +-- evaluate canonical permission
   v
ALLOW / DENY
```

### 3.3 Module-to-module machine request

```text
Registered service
   |
   | client_id + secret + target audience + requested scope
   v
Security token endpoint
   |
   +-- authenticate ServiceIntegration principal
   +-- verify ACTIVE
   +-- verify target audience grant
   +-- verify requested permission grant
   v
short-lived Security-signed JWT
   |
   v
Target module
   +-- signature / issuer / exp
   +-- actor_type=SERVICE_INTEGRATION
   +-- expected audience
   +-- required permission
```

No Tenant scope is required to authenticate or authorize the service principal itself.

---

## 4. Target physical database design

The plan is additive. Historical migrations remain unchanged.

### 4.1 Reused core tables

Retain:

- `security.security_principals`
- `security.users`
- `security.external_identities`
- `security.tenants`
- `security.modules`
- `security.permissions`
- `security.module_role_templates`
- `security.module_role_template_permissions`
- `security.platform_user_onboarding_settings`
- `security.platform_user_onboarding_requests`
- `security.admin_change_records`
- `security.security_events`
- `security.service_integrations`
- `security.principal_credentials`

### 4.2 USER status change

Modify `security.users.status` target allowed set for new writes to:

```text
PENDING | REJECTED | ACTIVE | SUSPENDED | DISABLED
```

Historical `INVITED` / `EXITED` values may remain readable during migration compatibility, but target APIs must not create new `INVITED` or `EXITED` state transitions.

Migration must reconcile any existing rows in legacy states before tightening the database constraint. No automatic mapping is allowed without data review.

### 4.3 Global role definition table — NEW

Proposed physical table:

```text
security.role_definitions
  role_key varchar(...) PK
  role_class varchar(...)  -- OPERATING | ADMIN | TEST
  display_name
  status                  -- ACTIVE | INACTIVE
  created_at_utc
  updated_at_utc
```

Seed fixed Phase-1 human classifications:

```text
PC
TL
PM
CRM
Executive
TenantAdmin
ModuleAdmin
SuperAdmin
TestUser
```

`ServiceIntegration` is not inserted as a human role definition; it remains a machine actor type/classification.

### 4.4 Platform default operating-role permissions — NEW

```text
security.platform_role_permission_defaults
  role_key FK role_definitions
  permission_key FK permissions
  source_catalog_version nullable
  status ACTIVE | RETIRED
  created_at_utc
  PRIMARY KEY(role_key, permission_key)
```

Only approved default bundles are seeded.

### 4.5 Tenant operating-role permissions — NEW

```text
security.tenant_role_permissions
  tenant_id FK tenants
  role_key FK role_definitions
  permission_key FK permissions
  assigned_by_user_id FK users
  assigned_at_utc
  PRIMARY KEY(tenant_id, role_key, permission_key)
```

Rules:

- `role_key` must be an OPERATING role for normal Tenant bundles.
- every referenced permission must exist and be ACTIVE when written;
- SuperAdmin updates are atomic replace operations at API/service level;
- changing a Tenant bundle does not create a new role.

### 4.6 Operating-role assignment — NEW

```text
security.user_tenant_operating_roles
  assignment_id uuid PK
  user_id FK users
  tenant_id FK tenants
  role_key FK role_definitions
  status ACTIVE | ENDED
  valid_from_utc nullable
  valid_to_utc nullable
  assigned_by_user_id FK users
  assigned_at_utc
  ended_at_utc nullable
```

Required database protections:

1. Partial unique index: one ACTIVE row per `(user_id, tenant_id)`.
2. Partial unique index: one ACTIVE row per `tenant_id` where `role_key='PM'`.
3. Application/service validation: role must be `OPERATING`.
4. Application/service validation: USER must be `ACTIVE` before a new operating assignment.
5. Global admin/operating exclusivity check in the same transaction.

The operating-role update service uses row/advisory locking or equivalent transaction serialization for `(user_id, tenant_id)` and PM replacement to prevent concurrency races.

### 4.7 Role-aligned Groups

Preferred Phase-1 implementation: **derived Groups**, not independently writable membership.

Reason:

- role assignment is already the authority;
- independent persisted membership creates synchronization risk;
- target Groups are only PC/TL/PM/CRM/Executive user collections.

Recommended physical approach:

- optionally retain `security.groups` rows as system metadata for display/name purposes;
- do not use `group_role_assignments` in target authorization;
- do not require `group_memberships` as authorization state;
- Group listing/users query `user_tenant_operating_roles` directly by `tenant_id + role_key`.

If persisted `group_memberships` is retained for UI compatibility, it must be transactionally derived from operating-role assignment and never be an independent grant source. The first implementation preference is to avoid the duplicate write.

### 4.8 Administrative-role assignment — NEW

```text
security.user_admin_role_assignments
  assignment_id uuid PK
  user_id FK users
  role_key FK role_definitions
  scope_type PLATFORM | TENANT | MODULE
  scope_id nullable
  status ACTIVE | ENDED
  assigned_by_user_id FK users nullable for bootstrap
  assigned_at_utc
  ended_at_utc nullable
```

Scope shape rules:

```text
SuperAdmin  -> scope_type=PLATFORM, scope_id=NULL
TenantAdmin -> scope_type=TENANT,   scope_id=<tenant UUID>
ModuleAdmin -> scope_type=MODULE,   scope_id=<module_key>
```

Required invariants:

- exactly one ACTIVE SuperAdmin in Phase 1;
- TenantAdmin uniqueness per `(user_id, tenant_id)`;
- ModuleAdmin uniqueness per `(user_id, module_key)`;
- administrative assignments may stack;
- a USER with any ACTIVE admin assignment may not have an ACTIVE operating assignment anywhere;
- a USER with any ACTIVE operating assignment may not receive an admin assignment.

The existing `platform_user_role_assignments` can remain for historical compatibility while SuperAdmin is migrated to the new scoped table. During transition there must be one canonical resolver only; double counting must not occur.

### 4.9 TestTenant and TestUser

TestTenant uses normal `security.tenants` with one canonical Tenant UUID selected/generated during implementation.

TestUser uses normal:

- `security.users`;
- `security.external_identities`;
- `security.role_definitions(TestUser)` classification;
- one explicit TestTenant association/configuration record as required by implementation.

Recommended new singleton/config table rather than overloading production operating role:

```text
security.phase1_test_identity
  singleton_id = 1
  user_id FK users UNIQUE
  tenant_id FK tenants UNIQUE
  status ACTIVE | INACTIVE
  created_at_utc
```

Authorization resolver rule:

```text
TestUser + configured TestTenant
  -> effective permissions = TestTenant PC bundle
```

No production operating-role assignment is created for TestUser.

The canonical TestTenant UUID and full exact Clerk TestUser subject are implementation inputs and must not be guessed.

### 4.10 Global deletion requests — NEW

```text
security.user_deletion_requests
  deletion_request_id uuid PK
  user_id
  requested_by_user_id
  requested_at_utc
  reason
  status REQUESTED | CANCELLED | COMPLETED | FAILED
  checked_by_user_id nullable
  checked_at_utc nullable
  outcome nullable
  correlation_id
```

Deletion request is not Tenant-scoped.

Phase-1 maker may be:

- USER self;
- Executive;
- TenantAdmin;
- ModuleAdmin;
- SuperAdmin.

The confirmed lifecycle diagram explicitly defines `ACTIVE -> DISABLED` for deletion request. The implementation must not silently broaden deletion-source states beyond the approved lifecycle. Requests from unsupported states return conflict until separately approved.

### 4.11 Deleted USER tombstone — NEW

Hard delete cannot leave audit FK dependency on the live USER row.

Proposed table:

```text
security.deleted_user_tombstones
  tombstone_id uuid PK
  deleted_user_id
  deletion_request_id
  safe_actor_reference / minimum approved identity snapshot
  deleted_at_utc
  retain_until_utc
  deletion_correlation_id
```

Default:

```text
retain_until_utc = deleted_at_utc + 21 days
```

Do not store:

- password;
- Clerk JWT/session token;
- machine credentials;
- client secrets;
- OTP;
- other authentication secrets.

A scheduled cleanup mechanism may remove expired tombstones after 21 days. Exact scheduler mechanism is implementation-level and should reuse existing runtime/job infrastructure if available rather than adding infrastructure solely for this purpose.

### 4.12 Platform-global ServiceIntegration grants — NEW around reused service identity

Reuse:

```text
security.security_principals
security.service_integrations
security.principal_credentials
```

Add:

```text
security.service_integration_audiences
  principal_id FK service_integrations
  audience
  status ACTIVE | ENDED
  assigned_by_user_id
  assigned_at_utc
  PRIMARY KEY(principal_id, audience)
```

```text
security.service_integration_permissions
  principal_id FK service_integrations
  permission_key FK permissions
  target_module
  status ACTIVE | ENDED
  assigned_by_user_id
  assigned_at_utc
  PRIMARY KEY(principal_id, target_module, permission_key)
```

`principal_tenant_scopes` and Tenant-scoped `principal_permission_grants` are not consulted for the target ServiceIntegration authorization path.

### 4.13 Machine token issuance audit

Do not require target platform-global service tokens to create a Tenant-scoped `access_sessions` row.

Instead, reuse `security_events` / admin audit for token-security events and service credential lifecycle. The existing `access_sessions` rows can remain for historical legacy/deferred flows.

This avoids reintroducing a fake Tenant merely to issue a platform-global service token.

---

## 5. Authorization resolver design

### 5.1 Resolve global USER

Input:

```text
provider = CLERK
provider_subject = Clerk sub
```

Rules:

1. active external identity must exist;
2. linked USER must exist;
3. security principal must be ACTIVE where retained as a principal gate;
4. USER status must be `ACTIVE` for protected application authorization.

### 5.2 Resolve SuperAdmin

If USER has ACTIVE SuperAdmin admin assignment:

```text
effective permissions = every ACTIVE permission in security.permissions
```

Do not copy a per-Tenant bundle.

The existing `0005` synchronization logic is reusable, but the runtime can also resolve SuperAdmin directly against ACTIVE permission catalogue. The implementation should use one canonical mechanism and tests must prove newly registered ACTIVE permissions are immediately/transactionally available according to the chosen mechanism.

### 5.3 Resolve TenantAdmin

For requested Tenant `T1`:

- USER must have ACTIVE `TenantAdmin(T1)` admin assignment;
- grant only TenantAdmin approved permissions scoped to T1;
- do not allow use against T2 unless separately assigned;
- TenantAdmin cannot change Tenant role bundles;
- TenantAdmin may suspend an ACTIVE USER according to Section 8, with a global status effect;
- deletion request remains a separately confirmed global USER operation.

### 5.4 Resolve ModuleAdmin

For target module:

- USER must have ACTIVE ModuleAdmin assignment for that module;
- module scope applies across Tenants;
- permissions are the approved ModuleAdmin permissions already listed in the solution design;
- operating-user permissions are not inherited automatically.

### 5.5 Resolve TestUser

If USER is configured TestUser and request Tenant is canonical TestTenant:

```text
effective permissions = TestTenant PC Tenant bundle
```

Otherwise deny TestUser protected production Tenant authorization.

### 5.6 Resolve operating USER

For ordinary employee:

1. select one ACTIVE `user_tenant_operating_roles` row for `(user, tenant)`;
2. read `tenant_role_permissions` for that role key;
3. required canonical permission must be present;
4. Group does not add permissions.

No permission union across multiple operating roles is allowed.

---

## 6. Human USER lifecycle implementation

### 6.1 Target first-party onboarding flow

Do not send human password/TOTP/OTP through Security.

Target sequence:

```text
1. Client obtains/uses platform onboarding key.
2. POST Security onboarding request with approved profile fields; no password.
3. Security creates global USER=PENDING + onboarding request.
4. Client completes Clerk first-party signup/authentication directly with Clerk.
5. Authenticated client calls Security bind endpoint with Clerk session JWT + onboarding request ID.
6. Security validates Clerk JWT locally and validates expected email/identity relationship.
7. Security binds Clerk subject to existing global USER.
8. USER remains PENDING.
9. SuperAdmin lists/reviews PENDING USER.
10. SuperAdmin changes PENDING -> ACTIVE or PENDING -> REJECTED.
11. Tenant/role assignment happens separately.
```

The existing `GlobalUserOnboardingService.bind_authenticated_clerk_user` is a strong base because it already checks the Clerk identity/email relationship and one-to-one binding. It must be invoked from first-party Clerk JWT context rather than Security receiving user credentials.

### 6.2 Status-transition authority matrix

| Transition/action | Allowed Phase-1 actor |
|---|---|
| `PENDING -> ACTIVE` | SuperAdmin only |
| `PENDING -> REJECTED` | SuperAdmin only |
| `ACTIVE -> SUSPENDED` | Executive or TenantAdmin within existing Tenant scope; SuperAdmin also has authority through all-permissions rule |
| `REJECTED -> ACTIVE` | SuperAdmin only |
| `SUSPENDED -> ACTIVE` | SuperAdmin only |
| `DISABLED -> ACTIVE` | SuperAdmin only |
| deletion request `ACTIVE -> DISABLED` | self, Executive, TenantAdmin, ModuleAdmin, SuperAdmin |
| hard DELETE of DISABLED USER | SuperAdmin only |

For Executive/TenantAdmin suspension, the caller's authority is established in an applicable Tenant context, but the Security USER status is global; therefore subsequent authorization fails in all Tenants.

### 6.3 Clerk synchronization

On `SUSPENDED` or `DISABLED`:

1. commit/establish Security denial state first;
2. revoke target live Security legacy USER sessions where still present;
3. request Clerk ban/session termination as defense in depth;
4. if Clerk sync fails, return/report synchronization failure but keep local USER non-ACTIVE and fail closed.

On SuperAdmin reactivation:

1. restore Clerk lifecycle as required;
2. only set Security USER ACTIVE when reactivation can complete safely under the selected ordering;
3. audit old/new state.

### 6.4 Hard delete coordinator

Preconditions:

- USER exists;
- USER is `DISABLED` due to a recorded deletion request;
- caller is the one ACTIVE SuperAdmin;
- deletion evidence exists.

Coordinator stages:

1. lock target USER/deletion request;
2. verify preconditions;
3. delete/retire Clerk identity/account as required;
4. snapshot minimum approved deletion evidence into tombstone independent of live USER FKs;
5. remove/end live operating/admin/test assignments;
6. revoke external identity mapping and live user-related credentials/sessions;
7. hard delete live USER/principal rows in FK-safe order;
8. mark deletion request/audit outcome using FK-independent evidence where needed;
9. make email reusable;
10. retain tombstone/deletion reference for 21 days.

Do not report success if the required live identity deletion cannot complete safely.

---

## 7. Role and Group implementation

### 7.1 No Tenant role creation

Retire target use of:

```text
POST /security/v1/admin/tenants/{tenantId}/roles
```

and other role-ID mutation semantics for fixed operating roles.

The fixed global role definition catalogue is read-only for normal Phase-1 API callers.

### 7.2 Operating role set/replace service

Target service transaction:

```text
set_operating_role(user, tenant, role_key, actor)
```

Steps:

1. validate USER ACTIVE;
2. validate Tenant ACTIVE;
3. validate role_key is one of PC/TL/PM/CRM/Executive;
4. reject if USER has any ACTIVE admin assignment;
5. if `PM`, lock/check no other active PM exists;
6. end existing active operating assignment for `(user,tenant)` if different;
7. insert new active assignment;
8. Group view automatically reflects new role;
9. audit before/after;
10. commit atomically.

Idempotent behavior: assigning the already-active same role returns current state without creating duplicate history.

### 7.3 Group implementation

Expose read-only logical groups:

```text
PC
TL
PM
CRM
Executive
```

Group APIs query operating assignments, not independent Group grants.

Retire active authorization use of:

- arbitrary Group creation;
- manual Group membership writes;
- Group-to-role writes;
- Group-derived role union.

Historical rows remain untouched until later cleanup decision.

---

## 8. Administrative-role implementation

### 8.1 SuperAdmin

Phase 1 has exactly one ACTIVE SuperAdmin.

Reuse `InitialSuperAdminProvisioningService` because it already:

- takes immutable Clerk `user_` ID;
- refuses replacement when another active SuperAdmin exists;
- creates global USER/external identity;
- audits provisioning.

Modify target provisioning/assignment persistence to the canonical v2 admin assignment model when introduced.

Implementation requires the full exact Clerk subject; the redacted value in the solution document must not be used literally.

### 8.2 TenantAdmin

Scope:

```text
one Tenant across modules
```

Default activities are those already approved in the solution design. Security implementation should map them to existing canonical Security permission keys wherever the semantics match, rather than inventing parallel keys.

TenantAdmin does not receive Tenant role-bundle modification authority.

`ACTIVE -> SUSPENDED` is allowed when the caller is TenantAdmin in the applicable Tenant context; effect is global.

### 8.3 ModuleAdmin

Scope:

```text
one module across all Tenants
```

Use the exact Audit Core and DI ModuleAdmin permission lists approved in `SECURITY_SOLUTION_DESIGN_v2.0.md`.

Do not add operating permissions merely because the USER is ModuleAdmin.

### 8.4 Admin/operating exclusivity

Every admin assignment and operating assignment service must call the same invariant checker inside the write transaction.

Do not rely only on UI prevention.

---

## 9. Permission catalogue and default seed implementation

### 9.1 Module catalogue

Retain current module catalogue registration/update service and permission retirement conflict checks.

Add explicit read API:

```text
GET /security/v1/platform/modules/{moduleKey}/permissions
```

This should be a projection of the existing registered catalogue, not a second permission store.

### 9.2 Platform default bundles

Seed platform defaults exactly from `SECURITY_SOLUTION_DESIGN_v2.0.md` Section 21.6 for:

- PC;
- TL;
- PM;
- CRM.

Do not alter those lists during implementation unless a canonical permission is missing/retired in the registered module catalogue; if that occurs, fail the seed validation and surface the catalogue conflict.

Executive default is implemented from the approved rule in Section 21.7:

- Audit Core: all current approved read permissions + normal non-destructive update/write permissions;
- exclude create/delete/upload/submit/verify/decide/resolve/execute/publish/admin-manage unless separately approved;
- DI: read-only;
- no DI configuration writes.

Because Executive is a rule-based default rather than an explicitly enumerated list in the solution design, implementation must produce the concrete generated list from the registered catalogues and include that list in review/tests before migration is committed. No name should be invented.

### 9.3 Tenant creation seeding

Tenant creation transaction/initialization flow:

```text
create Tenant
   -> create/copy current approved PC bundle
   -> TL bundle
   -> PM bundle
   -> CRM bundle
   -> Executive bundle
```

If any required default references a missing/non-ACTIVE permission, Tenant initialization must not silently drop that permission. Return an initialization/configuration error for administrative correction.

### 9.4 Tenant override

Only SuperAdmin may atomically replace:

```text
(tenant_id, role_key) -> permission set
```

Each requested permission must already exist and be ACTIVE.

Audit records capture before/after permission sets.

---

## 10. TestUser / TestTenant implementation

Implementation sequence:

1. create/select one canonical TestTenant UUID in Security;
2. store/mark it as the configured TestTenant;
3. seed normal Tenant PC/TL/PM/CRM/Executive defaults;
4. bind the exact existing Clerk TestUser subject to one global Security USER if not already mapped;
5. configure TestUser -> TestTenant test association;
6. authorization resolver maps TestUser's TestTenant permissions to TestTenant PC bundle;
7. deny TestUser production Tenant role/admin assignment in Phase 1;
8. expose canonical TestTenant ID for dependent Audit Core/DI provisioning/configuration.

Security must not create different TestTenant IDs for each module.

---

## 11. ServiceIntegration implementation design

### 11.1 Reuse base

Reuse:

- `security_principals.actor_type='SERVICE_INTEGRATION'`;
- `service_integrations`;
- `principal_credentials`;
- Argon2 secret hashing/verification already used by current machine access;
- Security RSA signing key and JWKS endpoint;
- client-credentials request handling patterns in `api/routes/access.py`;
- existing canonical permission validation.

### 11.2 Remove Tenant dependency from target service token path

Current machine flow requires:

```text
tenant_id
principal_tenant_scopes
principal_permission_grants
```

Target ServiceIntegration does not.

New resolver uses:

```text
service principal
  + active credential
  + allowed audience
  + platform-global service permission grant
```

### 11.3 Target machine JWT claim shape

Required claims:

```text
iss
sub = service identity
actor_type = SERVICE_INTEGRATION
aud = requested approved target
exp
iat
jti
permissions[]
```

Do not require target machine tokens to carry:

- tenant_id;
- USER role;
- device_id;
- location_id;
- human authorization version.

`TokenService` should be refactored so machine-token claim validation is separate from the retired human access-token claim shape.

### 11.4 Audience enforcement

Token request includes a target audience.

Security issues only if an ACTIVE `service_integration_audiences` grant exists for the caller and requested audience.

Target module validates its expected audience locally.

### 11.5 Service-specific permissions

Requested scope is intersected/validated against platform-global service grants for the target module.

No service gets all module permissions merely because its actor type is ServiceIntegration.

### 11.6 Service token endpoint reuse recommendation

Current `POST /oauth/token` with `grant_type=client_credentials` is a strong reusable base and follows an established machine-token pattern.

Implementation recommendation:

- retain `/oauth/token` for `client_credentials`;
- remove `tenant_id` from target client-credentials request;
- add/use explicit target `audience` request parameter;
- validate service permissions globally;
- retire the USER token-exchange grant from Phase-1 active use.

The solution design also shows logical `POST /security/v1/service/token`. Before coding, choose one canonical URI. Preferred reuse choice is `/oauth/token`; if the solution-design URI must be preserved, implement it as the canonical route or a thin compatibility alias rather than duplicating token logic.

This URI choice is an **implementation approval**, not an architecture change.

### 11.7 Internal Security authorization caller

Audit Core/DI/Web call `/authorization/check` using a ServiceIntegration JWT with:

```text
aud = security
```

and an approved Security service permission allowing that backend to invoke the authorization capability.

No canonical permission key for this new integration operation is already approved in the reviewed catalogue. Do not invent it in code. Before migration, approve either:

- a dedicated Security integration permission key; or
- an explicitly approved existing Security permission whose semantics truly cover this operation.

The same rule applies to any new service-client administration permission not already represented by an existing approved Security key.

---

## 12. Target API/OpenAPI design

Exact Pydantic/OpenAPI models are created during implementation after this blueprint approval.

### 12.1 Human authentication rule for Security APIs

All protected human Security APIs:

```text
Authorization: Bearer <Clerk session JWT>
```

Dependency chain:

```text
verify Clerk JWT -> resolve USER -> validate USER status -> in-process permission/scope policy
```

No PlatformAdmin Security JWT is required.

### 12.2 USER APIs

#### List/search

```text
GET /security/v1/platform/users
```

Inputs:

- `status` optional: PENDING/REJECTED/ACTIVE/SUSPENDED/DISABLED;
- search text optional;
- pagination;
- deterministic sort.

Caller: human admin.

Base read permission: reuse existing `security.user.read` where applicable.

#### Detail

```text
GET /security/v1/platform/users/{userId}
```

Returns only Security-owned USER/identity/lifecycle data.

#### Status

Canonical target:

```text
PATCH /security/v1/users/{userId}/status
```

Request contains target status and optional reason/reason code.

Authorization is transition-policy based, not merely one broad permission check.

Important transition rules are listed in Section 6.2.

#### Hard delete

```text
DELETE /security/v1/platform/users/{userId}
```

SuperAdmin only.

Returns success only after hard-delete coordinator completes required steps.

### 12.3 Tenant APIs

Reuse existing logical APIs:

```text
POST  /security/v1/platform/tenants
GET   /security/v1/platform/tenants
GET   /security/v1/platform/tenants/{tenantId}
PATCH /security/v1/platform/tenants/{tenantId}
POST  /security/v1/platform/tenants/{tenantId}/activate
```

Use current `security.tenant.*` canonical permissions where semantics match.

### 12.4 Role APIs

```text
GET /security/v1/roles
```

Read fixed global human role catalogue.

```text
PUT /security/v1/tenants/{tenantId}/users/{userId}/operating-role
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

Set/replace and remove only.

Use existing `security.role.read` / `security.role.assign` permissions where their semantics match. Tenant role creation permissions are not used for the target operating-role catalogue.

### 12.5 Group APIs

Read-only Phase-1 surface:

```text
GET /security/v1/tenants/{tenantId}/groups
GET /security/v1/tenants/{tenantId}/groups/{roleKey}
GET /security/v1/tenants/{tenantId}/groups/{roleKey}/users
```

Reuse `security.group.read` for read authorization where applicable.

No Group create/update/member/role grant API is part of the target Phase-1 authorization model.

### 12.6 Admin assignment APIs

TenantAdmin:

```text
PUT    /security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin
DELETE /security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin
```

ModuleAdmin:

```text
PUT    /security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin
DELETE /security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin
```

No second-SuperAdmin assignment API in Phase 1.

Use existing approved Security admin-management permission where semantically valid; if a dedicated admin-assignment permission is required, approve it before coding rather than inventing it.

### 12.7 Permission discovery/default APIs

```text
GET /security/v1/platform/modules
GET /security/v1/platform/modules/{moduleKey}
GET /security/v1/platform/modules/{moduleKey}/permissions
PUT /security/v1/platform/modules/{moduleKey}/catalog

GET /security/v1/platform/role-defaults/{roleKey}
GET /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
PUT /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
```

Module read/manage and permission read should reuse existing canonical permissions where applicable.

Tenant role-bundle PUT is SuperAdmin-only regardless of a lower-scope admin possessing a generic role-read/assign capability.

### 12.8 Runtime human authorization API

```text
POST /security/v1/authorization/check
Authorization: Bearer <ServiceIntegration JWT aud=security>
```

Request:

```json
{
  "clerkSubject": "<validated Clerk subject>",
  "tenantId": "<tenant UUID or null for platform-scope operation>",
  "permissionKey": "<registered canonical permission>"
}
```

Response:

```json
{
  "allowed": true,
  "userId": "<global USER UUID>",
  "decisionId": "<correlation/decision id>",
  "classification": "PC"
}
```

Deny response should not expose sensitive authorization internals to untrusted callers; internal registered services may receive stable reason codes as needed for diagnostics.

Behavior:

- authenticate ServiceIntegration caller;
- ensure service is authorized to call Security AuthZ;
- reject unregistered permission key;
- resolve human USER;
- require ACTIVE status;
- evaluate scope/classification/current bundle;
- return allow/deny;
- no Dealer/Outlet evaluation in Security.

### 12.9 Service token API

Reuse-oriented target request based on current OAuth route:

```text
POST /oauth/token
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
audience=di
scope=...
```

No Tenant ID in target service client-credentials request.

Alternative canonical URI from solution design remains an implementation naming approval as noted in Section 11.6.

---

## 13. Endpoint-to-permission / caller matrix

This matrix uses existing canonical permissions where confirmed. Rows that require a new service-administration/integration permission are deliberately marked `APPROVAL REQUIRED` rather than inventing a key.

| API/capability | Caller type | Authentication | Permission / policy | Scope |
|---|---|---|---|---|
| List global USERs | Human admin | Clerk JWT | `security.user.read` | platform/read filtering |
| PENDING -> ACTIVE | SuperAdmin | Clerk JWT | SuperAdmin classification + all-permission invariant | global |
| PENDING -> REJECTED | SuperAdmin | Clerk JWT | SuperAdmin classification | global |
| ACTIVE -> SUSPENDED | Executive | Clerk JWT | transition policy + applicable Tenant context | global USER effect |
| ACTIVE -> SUSPENDED | TenantAdmin | Clerk JWT | TenantAdmin assignment in applicable Tenant | global USER effect |
| Reactivate USER | SuperAdmin | Clerk JWT | SuperAdmin classification | global |
| Request self delete | Human self | Clerk JWT | target user == caller | global |
| Request delete | Executive/TenantAdmin/ModuleAdmin/SuperAdmin | Clerk JWT | confirmed maker classification/scope policy | global |
| Hard DELETE USER | SuperAdmin | Clerk JWT | SuperAdmin classification | global |
| Create Tenant | SuperAdmin | Clerk JWT | `security.tenant.create` | platform |
| Read Tenant | approved admin | Clerk JWT | `security.tenant.read` | according to admin scope |
| Set operating role | SuperAdmin/TenantAdmin where approved | Clerk JWT | `security.role.assign` + scope/invariant policy | Tenant |
| Read Groups | approved admin | Clerk JWT | `security.group.read` | Tenant |
| Read module catalogue | approved admin | Clerk JWT | `security.module.read` | platform/scope policy |
| Read permissions | approved admin | Clerk JWT | `security.permission.read` | catalogue |
| Update module catalogue | SuperAdmin / approved Module catalogue admin if retained | Clerk JWT | `security.module.manage` | platform |
| Read Tenant role bundle | approved admin | Clerk JWT | existing read permissions + scope policy | Tenant |
| Update Tenant role bundle | SuperAdmin only | Clerk JWT | SuperAdmin classification | Tenant |
| Authorization check | Registered backend service | ServiceIntegration JWT | **APPROVAL REQUIRED for exact canonical service permission** | platform service -> human Tenant context in payload |
| Service token issuance | Registered service | client ID/secret | credential + audience + granted scopes | platform-global |
| Service registry admin | SuperAdmin | Clerk JWT | **APPROVAL REQUIRED if no existing permission is adopted** | platform |

---

## 14. Migration and reconciliation plan

No historical migration is edited.

### 14.1 Additive migration sequence

Recommended sequence:

1. add new role definition/default/Tenant bundle tables;
2. add new operating-role assignment table and indexes;
3. add scoped admin assignment table/invariants;
4. add TestUser/TestTenant configuration table if approved;
5. add deletion request + tombstone tables;
6. add platform-global ServiceIntegration audience/permission tables;
7. adjust USER status constraints only after data reconciliation;
8. seed fixed global role definitions;
9. seed approved default bundles;
10. migrate/reconcile active legacy role data;
11. migrate the one SuperAdmin assignment to canonical admin assignment representation while preserving the existing all-ACTIVE permission invariant;
12. provision/configure TestTenant and TestUser with exact implementation inputs;
13. register/reconcile platform-global service clients from existing machine principals;
14. deploy new authorization resolver/APIs;
15. migrate human Security routes to Clerk JWT dependencies;
16. switch machine client-credentials issuance to platform-global audience model;
17. retire old human Security token routes from active routing after dependent clients are migrated;
18. leave historical/deferred tables intact.

### 14.2 Mandatory data reconciliation before role cutover

Produce a report for:

- users with >1 active direct role in same Tenant;
- users with effective roles added through Groups;
- users with both legacy platform/admin and operating roles;
- Tenants with >1 user that would become PM;
- custom Tenant roles with no mapping to PC/TL/PM/CRM/Executive;
- permissions granted only through custom Group-role chains;
- arbitrary Groups not equivalent to role-aligned Group;
- users in legacy INVITED/EXITED states;
- multiple/incorrect SuperAdmin assignments;
- machine principals with Tenant-only scopes/grants that need platform-global audience mapping.

Do not auto-pick winners for conflicts. Produce the report and require explicit remediation/mapping.

### 14.3 Existing Tenant role objects

Do not delete them during first migration.

After target tables are populated and verified:

- stop writes to legacy Tenant role creation/assignment APIs;
- target runtime reads only new role tables;
- legacy rows remain historical/compatibility data until separate cleanup approval.

### 14.4 Existing arbitrary Groups

Do not delete rows initially.

Target authorization stops using `group_role_assignments` and Group-derived union.

Target Group APIs return only role-aligned operating collections.

---

## 15. Device/Geo/Schedule/VPN deferral plan

Keep current:

- schema;
- migrations;
- administration code;
- tests where they validate the legacy/deferred feature independently.

Do not require these controls in:

- Clerk-JWT identity validation;
- `/authorization/check`;
- Security's in-process v2 permission authorization;
- SuperAdmin/TenantAdmin/ModuleAdmin/operating role authorization.

Mark corresponding runtime access-session issuance route as legacy/deferred once human Security token issuance is retired.

Do not remove the feature; future Phase 2 can reintroduce selected controls as separate conditional policy checks without changing the global USER/RBAC architecture.

---

## 16. Code-level implementation work breakdown

No file is changed by this blueprint. The following is the expected code work after approval.

### Step 1 — Target schema migration

**Reuse:** existing migration framework/schema.  
**New:** one or more additive v2 migrations.  
**Affects:** role definitions, bundles, admin assignments, deletion, service grants, statuses.  
**Tests:** migration up test, constraints, conflict fixtures.

### Step 2 — Clerk human authentication dependency

**Reuse:** `api/dependencies.py`, `adapters/identity.py`.  
**Modify:** Clerk verifier configuration/JWKS handling as required; human route dependencies.  
**Retire active use:** `ClerkCredentialService` for human route login.  
**Tests:** valid/expired/invalid issuer/invalid azp/unmapped Clerk subject.

### Step 3 — Global USER lifecycle service

**Reuse:** `GlobalUserOnboardingService`, global USER tables.  
**Modify:** first-party bind flow, REJECTED, transition policy, SuperAdmin-only approval/reactivation, Executive/TenantAdmin suspension.  
**New:** transition policy/coordinator abstraction if useful to prevent route-level duplication.  
**Tests:** every allowed/denied transition.

### Step 4 — Deletion coordinator

**New:** deletion request/tombstone repository/service and hard-delete coordinator.  
**Reuse:** Clerk backend lifecycle adapter, audit mechanisms.  
**Tests:** maker rules, DISABLED, hard-delete SuperAdmin-only, failure rollback/partial dependency behavior, 21-day retention metadata.

### Step 5 — Role resolver and assignment

**Reuse:** canonical permission validation and audit patterns.  
**Replace:** `TenantRbacGateService` additive operating-role semantics.  
**New:** operating-role repository/service using role_key.  
**Tests:** one role/Tenant, different roles across Tenants, PM uniqueness, idempotent replace.

### Step 6 — Role-aligned Groups

**Reuse:** only read presentation concepts where useful.  
**Retire active:** Group create/member/role mutation for authorization.  
**New/modify:** read-only Group queries from operating-role assignment.  
**Tests:** PC->TL moves Group view; PM Group max one; no Group-derived extra permission.

### Step 7 — Admin assignments

**Reuse:** initial SuperAdmin provisioning logic and audit patterns.  
**New:** scoped admin assignment persistence/resolver.  
**Tests:** TenantAdmin scope, ModuleAdmin scope, admin stacking, global operating/admin exclusivity, exactly one SuperAdmin.

### Step 8 — Default/Tenant role bundles

**Reuse:** module catalogue, permission registry, template source data.  
**New:** platform defaults + Tenant bundles.  
**Tests:** exact PC/TL/PM/CRM seed, generated Executive review list, TestUser PC inheritance, SuperAdmin all-ACTIVE.

### Step 9 — Authorization check API

**New:** `/authorization/check` route, request/response schema, ServiceIntegration caller dependency.  
**Reuse:** identity mapping, permission validator, new resolver.  
**Tests:** allowed, denied, non-ACTIVE USER, no role, wrong Tenant, invalid permission, backend caller not authorized, Security fail closed at clients.

### Step 10 — ServiceIntegration platform-global token flow

**Reuse:** `/oauth/token` parsing/Basic client auth, machine secret verification, RSA signing/JWKS.  
**Modify:** remove tenant grant dependency, add audience, new machine claim shape, global scopes.  
**Retire:** USER token-exchange grant from active Phase 1.  
**Tests:** invalid client, expired/revoked credential, invalid audience, excessive scope, correct aud token, wrong aud rejection, external unknown client.

### Step 11 — Platform/Tenant/module admin routes

**Reuse:** Tenant CRUD, module catalogue routes.  
**Modify:** human authentication from PlatformAdmin JWT to Clerk JWT + in-process AuthZ.  
**Tests:** SuperAdmin global, TenantAdmin limited Tenant, ModuleAdmin limited module.

### Step 12 — Retire old human token flow

**Retire active routes/services:** human `/auth/login`, human access-session token issuance, PlatformAdmin Security JWT login, USER token exchange.  
**Keep:** code/history until dependent tests/clients are migrated and explicit cleanup approved.  
**Tests:** target human APIs reject Security human legacy JWT where Clerk JWT is required.

---

## 17. Test strategy

### 17.1 Human authentication

- valid Clerk JWT accepted;
- expired Clerk JWT denied;
- invalid issuer/signature denied;
- unauthorized party denied;
- unmapped Clerk subject denied for protected app operations;
- DEV mock accepted only in permitted environments.

### 17.2 USER status

- PENDING denied protected access;
- REJECTED denied;
- SUSPENDED denied;
- DISABLED denied;
- only SuperAdmin approves PENDING;
- only SuperAdmin rejects PENDING;
- Executive can suspend only under applicable Tenant scope policy;
- TenantAdmin can suspend only under applicable Tenant scope policy;
- SuperAdmin reactivation works;
- non-SuperAdmin reactivation denied.

### 17.3 Role invariants

- one operating role per USER/Tenant;
- same USER can hold different roles in different Tenants;
- second PM rejected transactionally;
- admin USER cannot receive operating role;
- operating USER cannot receive admin role;
- admin roles stack legally.

### 17.4 Groups

- five role-aligned groups shown per Tenant as applicable;
- group members equal operating assignment query;
- role replace changes group view;
- no independent Group write grants authorization;
- legacy Group-role grants ignored by target authorization.

### 17.5 Permission bundles

- exact approved PC default;
- exact approved TL default;
- exact approved PM default;
- exact approved CRM default;
- Executive generated list reviewed against registered catalogues;
- Tenant copy created on initialization;
- Tenant override affects only target Tenant;
- retired/nonexistent permission cannot be written;
- SuperAdmin obtains every ACTIVE permission including newly registered module permission.

### 17.6 TestUser/TestTenant

- exact Clerk TestUser maps to configured TestUser;
- TestUser authorized only in TestTenant;
- TestUser effective permissions equal TestTenant PC bundle;
- TestUser cannot receive production operating/admin assignment.

### 17.7 Deletion

- self delete request -> DISABLED;
- Executive/TenantAdmin/ModuleAdmin/SuperAdmin maker cases;
- final delete non-SuperAdmin denied;
- hard delete requires recorded request + DISABLED;
- same SuperAdmin maker/checker allowed;
- Clerk dependency failure does not report false success;
- live USER removed on successful hard delete;
- email becomes reusable;
- tombstone independent of USER FK;
- retention deadline = +21 days;
- no secrets in tombstone/audit.

### 17.8 ServiceIntegration

- valid registered service credential;
- unknown client denied;
- wrong secret denied;
- revoked/expired credential denied;
- wrong target audience denied;
- excessive scope denied;
- service JWT has expected actor type and audience;
- expired machine JWT denied;
- fake/untrusted JWT denied;
- Security JWT for `aud=security` rejected by DI;
- one service's grants do not confer another service's access;
- no Tenant scope required for platform-global service principal.

### 17.9 Authorization check

- valid backend + active human + permission -> allow;
- valid backend + inactive human -> deny;
- backend without Security AuthZ service privilege -> deny;
- arbitrary browser call without machine identity -> deny;
- unregistered permission key -> deny/error;
- role permission absent -> deny;
- SuperAdmin -> allow for any ACTIVE permission;
- TenantAdmin/module scope boundaries enforced;
- Security internal routes use same resolver in-process.

### 17.10 Deferred controls

Regression tests should prove Device/Geo/Schedule/VPN code remains intact where directly exercised, while v2 authorization tests prove those inputs are not required by `/authorization/check` or Clerk-JWT Security API authorization.

---

## 18. Operational and failure rules

1. Security authorization unavailable -> protected backend operation fails closed.
2. Clerk JWT invalid -> deny before authorization.
3. Machine token invalid/wrong audience -> deny before target operation.
4. USER status change to non-ACTIVE affects the next synchronous authorization decision immediately.
5. Tenant role-bundle update affects subsequent decisions without human token reissue.
6. Audit Core remains responsible for Dealer/Outlet business-scope checks.
7. DI remains outside onboarding.
8. Partial Web BFF orchestration success must be reported accurately; Security role success does not imply Audit Core Dealer/Outlet assignment success.
9. No service credential/plaintext secret is logged.
10. No human JWT or machine JWT is stored in audit records.

---

## 19. Explicitly retired/deferred active behavior

### Retire from Phase-1 active human flow

- Security-issued human access JWT;
- PlatformAdmin Security JWT;
- Security-owned human credential login facade;
- user token exchange/delegated token grant;
- Tenant-owned arbitrary operating role creation;
- multiple/additive operating roles;
- arbitrary Group->Role permission inheritance;
- Group-derived effective permission union;
- Tenant membership as human authorization prerequisite.

### Keep but defer

- Device registration as a mandatory access gate;
- geofence/location as a mandatory access gate;
- schedules as a mandatory access gate;
- VPN/network-risk as a mandatory access gate;
- human authorization-version/token invalidation mechanism;
- mTLS;
- distributed authorization projection/cache;
- additional SuperAdmins;
- Dealer/Outlet staffing ratios;
- arbitrary custom Groups.

---

## 20. Implementation inputs / approvals required before coding specific items

These are not architecture questions and must not be guessed:

1. Full exact unredacted Clerk subject for the one SuperAdmin.
2. Full exact unredacted Clerk subject for TestUser.
3. Canonical TestTenant UUID/code/name.
4. Exact short-lived ServiceIntegration token TTL.
5. Service credential validity/rotation interval.
6. Canonical token endpoint URI choice: reuse `/oauth/token` client_credentials (recommended) versus canonical `/security/v1/service/token`/alias.
7. Exact canonical Security permission key for a ServiceIntegration principal to invoke `/authorization/check`, unless an existing approved key is explicitly selected.
8. Exact permission key(s) for ServiceIntegration registry administration if existing Security admin permissions are not intentionally reused.
9. Concrete initial ServiceIntegration registrations and their approved audience/permission matrices (for example Audit Core, DI, Web), derived from actual module integration needs rather than broad grants.
10. Concrete generated Executive default permission list must be reviewed against the registered Audit Core/DI catalogues before seed migration is finalized.

No code should invent values for items 1-9.

---

## 21. Recommended implementation order

```text
1. Approve this implementation blueprint
2. Resolve implementation inputs in Section 20 that block first migration/API code
3. Add additive target schema
4. Add Clerk-JWT human dependency + common authorization resolver
5. Implement USER lifecycle/transition policy
6. Implement deletion request/hard-delete/tombstone
7. Implement global role definitions + operating assignments
8. Implement role-aligned Group reads
9. Implement scoped admin assignments + SuperAdmin migration
10. Implement platform defaults + Tenant role bundles
11. Configure TestTenant/TestUser
12. Implement platform-global ServiceIntegration grants
13. Refactor machine token issuance/JWT audience model
14. Implement /authorization/check
15. Rewire Security human admin/Tenant/module routes to Clerk JWT + in-process AuthZ
16. Run data reconciliation report
17. Migrate clean legacy assignments into target tables
18. Cut target runtime reads to new RBAC model
19. Retire old human Security token/login/token-exchange active routes
20. End-to-end Security tests
21. Only after Security is proven, align dependent Audit Core/DI contracts in their own approved changes
```

---

## 22. Definition of implementation-ready

Security v2 Phase-1 is ready for code implementation only when:

- this blueprint is reviewed/approved;
- required exact Clerk/TestTenant inputs are supplied;
- any new canonical Security integration permission names are approved;
- the ServiceIntegration endpoint URI and token TTL are selected;
- the initial service audience/permission matrix is approved;
- existing `dev` data reconciliation is understood sufficiently to write deterministic migrations.

Security v2 Phase-1 is implementation-complete only when:

- Clerk session JWT is the active human authentication token;
- Security no longer issues active human access JWTs;
- live synchronous Security authorization enforces the target role/admin/test model;
- one operating role/User/Tenant and one PM/Tenant are enforced;
- Group authorization is role-aligned and non-additive;
- the one SuperAdmin has every ACTIVE registered permission;
- TenantAdmin and ModuleAdmin scope tests pass;
- PENDING approval/rejection is SuperAdmin-only;
- Executive/TenantAdmin suspension policy passes;
- deletion and 21-day retention tests pass;
- TestUser/TestTenant behavior passes;
- ServiceIntegration is platform-global, audience-restricted and least-privilege;
- unregistered/external machine callers cannot obtain or use valid target tokens;
- Device/Geo/Schedule/VPN code remains available but is not a mandatory Phase-1 authorization gate;
- legacy Tenant role/Group/human-token state no longer participates in the target runtime authorization result.
