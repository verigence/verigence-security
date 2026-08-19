# Verigence Security — Phase-1 Implementation Design

**Version:** 2.0  
**Status:** DRAFT FOR IMPLEMENTATION REVIEW  
**Date:** 2026-08-19  
**Repository:** `verigence/verigence-security`  
**Target branch:** `dev`  
**Authoritative architecture:** `docs/SECURITY_SOLUTION_DESIGN_v2.0.md`

> This document is an implementation blueprint only. It does not authorize application-code or migration changes. It translates the approved Security v2.0 solution design into a concrete reuse, data, API, migration and test plan. Where current `dev` implementation conflicts with the approved solution design or with implementation decisions explicitly confirmed after that design review, the confirmed target decisions win. No Audit Core or DI file is changed by this document.

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
6. Human user creation, email verification and credential authentication use the Clerk Backend API **through Security only**; Web/Mobile, Web BFF, Audit Core and DI do not integrate with Clerk.
7. Security issues the Verigence human access JWT after successful Clerk-backed authentication and separately issues JWTs for machine/service identities; human and machine token semantics remain distinct.
8. Human authorization is synchronous and fail-closed; the Security human JWT proves authenticated USER identity but does not replace live Security authorization.
9. Device/Geo/Schedule/VPN capabilities are retained but deferred from the active Phase-1 human authorization path.
10. Administrative endpoints are human-admin-only and explicitly reject `SERVICE_INTEGRATION` callers.
11. Permission classification into `FUNCTIONAL` versus `ADMIN` is deferred to Phase 2; Phase 1 keeps the current permission catalogue structure unchanged.
12. Canonical login is global and requires `identifier + password`; `tenantId` is not part of login. Client Device ID / Geo request-context headers may be present but are optional, not persisted and not access gates in Phase 1.
13. Canonical signup uses first name, last name, email, mobile and password in the Security request body; the user-facing Verigence Identifier continues through `X-Onboarding-Key`. Optional Device ID / Geo request-context headers are not persisted or bound to onboarding.
14. Phase 1 does not require TOTP/MFA in the canonical signup/login contract.

### 1.1 Confirmed implementation decisions

The following decisions are binding for Phase 1:

- Device / Geo / Schedule / VPN controls remain in the repository/database but are not active Phase-1 human authorization gates.
- Optional Device ID / Geo headers may be sent by the client on signup/login, but Security does not require, persist or evaluate them in the Phase-1 authentication/onboarding path; no database migration is required for that request context.
- `/security/v1/auth/login` request body is `identifier + password` only; it has no `tenantId`, mandatory `deviceId`, mandatory Geo or TOTP/MFA field.
- `/security/v1/onboarding/users` keeps `firstName`, `lastName`, `email`, `mobile`, `password`; the Verigence Identifier remains the existing `X-Onboarding-Key` header.
- `PENDING -> ACTIVE` and `PENDING -> REJECTED` are SuperAdmin-only actions.
- `ACTIVE -> SUSPENDED` may be initiated by `Executive` and `TenantAdmin` within their applicable Tenant scope. The USER status is global, therefore suspension denies access across all Tenants. SuperAdmin also retains the capability through its all-permissions authority.
- `ServiceIntegration` principals are platform-global, not Tenant-scoped.
- ServiceIntegration tokens have a **4-hour TTL**.
- The canonical machine-token endpoint is `POST /security/v1/service/token`.
- Existing `/oauth/token` machine-token behavior is deprecated and removed from the target active contract after migration.
- Registered ServiceIntegration identities are intended for broad module-to-module access. Phase 1 does not maintain per-service functional permission grants.
- Administrative/control-plane endpoints require a human authenticated through the canonical Security human authentication boundary and reject `SERVICE_INTEGRATION` regardless of the module.
- Audience restriction remains mandatory in machine JWTs to prevent a token issued for one module being replayed against another module.
- Permission classification/segregation is deferred to Phase 2.
- `/security/v1/auth/login` is the canonical human login facade for ordinary USERs and human administrative/test classifications; separate PlatformAdmin login/token issuance is not a target authentication model.
- Human signup/login secrets remain transient through Security and must never be persisted, audited, traced, cached or logged.

### 1.2 Exact Clerk identities — CONFIRMED

These exact Clerk subjects are authoritative for Phase 1:

```text
SuperAdmin
user_3I7HFuZZiFC9K2muiweXFRoeoud

TestUser
user_3I7FdD5Pkmydsp23OfjH9hBMxpN
```

They must be treated as immutable identity inputs. Do not substitute the previously abbreviated values and do not reverse these identities.

---

## 2. Current implementation inventory and disposition

### 2.1 Identity and human authentication

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.users` | Security human USER | Keep global USER; status model changes | **REUSE WITH MODIFICATION** |
| `security.external_identities` | Clerk/DEV_MOCK subject mapping | Keep one Clerk subject -> one global USER | **REUSE AS-IS / MINOR MODIFICATION** |
| `adapters/identity.py::ClerkJwtIdentityProvider` | Local Clerk JWT verification | Not part of target Verigence client/resource-server human authentication; retain only if needed historically/provider-internally and remove from active human route dependency | **RETIRE FROM ACTIVE HUMAN FLOW / KEEP HISTORICALLY** |
| `api/dependencies.py::identity_from_token` | Select Clerk/DEV mock identity verifier | Rewire protected human routes to validate the Security-issued human access JWT and resolve the global USER; DEV mock remains environment-limited | **REUSE WITH MODIFICATION** |
| `services/clerk_credentials.py` human password brokerage | Security receives the human identifier/password and calls Clerk Backend API; current code also contains TOTP logic | Retain as the Security-only Clerk password-verification boundary; keep secrets transient/redacted and remove TOTP as an active Phase-1 login requirement | **REUSE WITH MODIFICATION** |
| `api/routes/access.py::POST /security/v1/auth/login` | Clerk backend credential auth + Tenant/device/Geo access-session issuance | Retain as the canonical human login facade, but remove Tenant/device/Geo/TOTP coupling and issue the global identity-oriented Security human token | **REUSE WITH MODIFICATION** |
| `services/platform_admin_token.py` | Separate Security-issued human Platform Admin JWT model | Do not keep a separate PlatformAdmin authentication/token model; admins use the canonical Security human login/token boundary | **RETIRE DUPLICATE HUMAN AUTH MODEL** |
| `api/routes/platform_admin.py::/auth/login` | Separate Clerk credential auth + Platform Admin JWT | Retire as duplicate authentication surface; use canonical `/security/v1/auth/login` plus Security authorization classification | **RETIRE ACTIVE DUPLICATE ROUTE** |

### 2.2 Global USER onboarding and lifecycle

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `platform_user_onboarding_settings` | Platform-global onboarding key | Retain; user-facing label is Verigence Identifier | **REUSE** |
| `platform_user_onboarding_requests` | Global onboarding workflow | Retain; align status transitions while preserving Security-mediated Clerk creation/email verification | **REUSE WITH MODIFICATION** |
| `GlobalUserOnboardingService` | Global USER lifecycle/onboarding | Strong base; modify REJECTED, deletion, transition authority while retaining Security-owned Clerk integration | **REUSE WITH MODIFICATION** |
| Current password/OTP self-onboarding facade | Security-mediated Clerk signup/email verification | Retain as target integration shape; keep first/last/email/mobile/password body + `X-Onboarding-Key`; do not add persisted Device/Geo onboarding fields | **REUSE WITH MODIFICATION** |
| `GET /platform/users` | Global USER listing | Retain and extend filtering/search/pagination/detail | **REUSE WITH MODIFICATION** |
| Current USER status route | ACTIVE/SUSPENDED/DISABLED/EXITED style lifecycle | Replace with approved PENDING/REJECTED/ACTIVE/SUSPENDED/DISABLED transition policy | **REUSE WITH MODIFICATION** |
| Current `EXITED` state | Legacy terminal state | Not part of target Phase-1 canonical statuses | **RETAIN HISTORICALLY; RETIRE FROM NEW FLOW** |

### 2.3 Tenant and permission catalogue

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.tenants` | Tenant source of truth | Retain | **REUSE** |
| `PlatformTenantService` and Tenant CRUD | Platform Tenant lifecycle | Retain; switch human auth dependency to canonical Security human JWT + in-process Security AuthZ | **REUSE WITH MODIFICATION** |
| `security.modules` | Registered module catalogue | Retain | **REUSE** |
| `security.permissions` | Canonical permission registry | Retain unchanged in Phase 1 | **REUSE** |
| `ModuleCatalogService` | Register/update module permissions/templates | Retain | **REUSE WITH MODIFICATION** |
| Existing module discovery APIs | Module discovery | Retain | **REUSE** |
| Missing explicit module-permissions read API | Permission discovery | Add thin API over existing catalogue | **NEW API OVER EXISTING DATA** |
| `module_role_templates` | Module role-template source material | Keep as source/default material; no Tenant role identity creation | **REUSE WITH MODIFICATION** |

### 2.4 Roles and Groups

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.roles` | Tenant-created role objects | No longer authoritative role identity | **RETIRE FROM TARGET ACTIVE MODEL** |
| `security.role_permissions` | Tenant role-ID permission mapping | Replace with `(tenant_id, role_key, permission_key)` | **REPLACE ACTIVE MODEL** |
| `security.user_role_assignments` | Additive user-to-Tenant-role assignments | Replace with exactly one operating role per USER/Tenant | **REPLACE ACTIVE MODEL** |
| Arbitrary Tenant role creation | Custom Tenant role identities | Not allowed for fixed Phase-1 operating roles | **RETIRE ACTIVE API** |
| `effective_user_permissions()` | Union direct roles + Group-derived roles + platform roles | Replace with classification-aware resolver | **REWRITE CORE QUERY/LOGIC** |
| `security.groups` | Arbitrary Tenant Groups | Retain only where useful for role-aligned presentation | **REUSE WITH MAJOR SIMPLIFICATION** |
| `group_memberships` | Independent Group membership | Operating-role assignment becomes authority | **REUSE ONLY IF DERIVED/SYNCHRONIZED** |
| `group_role_assignments` | Group can add role(s) | Conflicts with target | **RETIRE FROM ACTIVE AUTHORIZATION** |
| Group create/member/role mutation APIs | Arbitrary Group administration | Replace with role-aligned read APIs | **RETIRE/REPLACE** |

### 2.5 Platform/admin roles

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `platform_roles` | Platform role catalogue | Reuse only where aligned; human admins authenticate through the canonical Security human JWT | **REUSE WITH MODIFICATION** |
| `platform_user_role_assignments` | Platform role assignment | Useful base for SuperAdmin migration | **REUSE PARTIALLY** |
| `initial_super_admin.py` | Exact Clerk subject provisioning | Strongly aligned with one Phase-1 SuperAdmin | **REUSE WITH MODIFICATION** |
| SuperAdmin provisioning script | Operator provisioning entrypoint | Retain using confirmed exact Clerk subject | **REUSE** |
| `0005_super_admin_full_authority.sql` | Synchronizes SuperAdmin with all ACTIVE permissions | Retain invariant and extend runtime use consistently | **REUSE STRONGLY** |
| Legacy/current platform admin personas not in final taxonomy | Older control-plane model | Keep historically, remove from new assignment flow unless explicitly retained | **RETAIN HISTORICALLY** |

### 2.6 Machine / ServiceIntegration

| Current component | Current purpose | Target disposition | Classification |
|---|---|---|---|
| `security.security_principals` with `SERVICE_INTEGRATION` | Machine principal base | Retain | **REUSE** |
| `security.service_integrations` | Service integration identity metadata | Retain as canonical service identity table | **REUSE** |
| `security.principal_credentials` | Client ID + hashed secret + lifecycle | Retain | **REUSE** |
| `principal_tenant_scopes` | Tenant-scoped machine scope | Not used by target ServiceIntegration | **RETIRE FROM TARGET SERVICE AUTHZ** |
| `principal_permission_grants` | Tenant-scoped machine permission grants | Not used by target Phase-1 ServiceIntegration | **RETIRE FROM TARGET SERVICE AUTHZ** |
| `/oauth/token` client_credentials flow | Existing machine token issuance | Reuse underlying implementation patterns only | **DEPRECATE ENDPOINT / REUSE INTERNALS** |
| `/oauth/token` token-exchange grant | USER token delegation | Not required Phase 1 | **RETIRE/DEFER** |
| `TokenService` RSA signing/JWKS | Security-signed tokens | Retain signing/JWKS for both the canonical human access JWT and the distinct machine ServiceIntegration claim model | **REUSE WITH MODIFICATION** |
| Tenant-scoped machine `access_sessions` | Legacy service sessions | Not required for target platform-global machine auth | **RETAIN HISTORICALLY / DEFER** |

### 2.7 Device / Geo / Schedule / VPN

Keep existing tables, code, administration surfaces and tests where they validate the deferred feature itself.

Do not invoke these as mandatory checks in the Phase-1 Security-human-JWT + synchronous Security authorization path.

For canonical signup/login, optional Device ID / Geo request-context headers may be present. The Phase-1 implementation does not persist them, does not bind them to the global USER/login, and does not use them for an allow/deny decision. Existing Tenant-scoped device/location tables are therefore left unchanged and no new migration is added for this correction.

Classification: **DEFER FROM ACTIVE PHASE-1 HUMAN AUTHORIZATION; DO NOT DELETE**.

---

## 3. Target runtime component model

### 3.1 Human authentication and request to Security

```text
Web/Mobile
   |
   | POST /security/v1/auth/login
   | body: identifier + password
   | no tenantId
   | optional Device/Geo request-context headers may be present
   v
Security
   |
   +-- authenticate credentials through Clerk Backend API
   +-- Clerk subject -> global USER
   +-- require active USER/principal/identity mapping
   +-- do not require Device/Geo/Schedule/VPN in Phase-1 login
   +-- issue Security human access JWT
   |
   | later protected Security request with Security human JWT
   v
Security API
   |
   +-- validate Security human JWT
   +-- resolve global USER
   +-- USER status check
   +-- in-process Security authorization
   +-- execute Security operation
```

Security does not call its own `/authorization/check` endpoint for Security-owned human/admin operations.

Tenant context is introduced by the later protected operation/authorization request, not by the login request or human token identity establishment.

### 3.2 Human request to Audit Core or DI

```text
Human
   |
   | Security-issued human access JWT
   v
Audit Core / DI
   |
   +-- validate Security JWT locally using Security trusted signing/JWKS
   +-- extract trusted global Verigence USER identity
   |
   | backend's ServiceIntegration JWT, aud=security
   v
Security /authorization/check
   |
   +-- validate registered machine caller
   +-- resolve supplied USER identity
   +-- USER must be ACTIVE
   +-- resolve Tenant/admin/test authorization
   +-- evaluate requested human permission
   v
ALLOW / DENY
```

The machine caller's token proves the backend is a trusted Verigence internal service. The human permission being checked remains the USER's permission, not the machine's permission.

### 3.3 Module-to-module machine request

```text
Registered internal service
   |
   | client_id + secret + target audience
   v
POST /security/v1/service/token
   |
   +-- registered ServiceIntegration principal?
   +-- principal ACTIVE?
   +-- credential valid and ACTIVE?
   +-- requested audience is a registered Verigence module/security audience?
   v
Security issues 4-hour signed machine JWT
   |
   v
Target module
   +-- signature / issuer / expiry
   +-- actor_type=SERVICE_INTEGRATION
   +-- aud matches this target module
   +-- target endpoint is not human-admin-only
   v
ALLOW / DENY
```

Phase 1 does **not** maintain service-specific functional permission grants or Tenant scopes for machine callers.

### 3.4 Administrative endpoint rule

Administrative/control-plane endpoints include operations such as:

- global USER approval/rejection/suspension/reactivation/deletion administration;
- Tenant creation/lifecycle administration;
- operating/admin role assignment;
- Tenant role-bundle modification;
- module/security configuration administration;
- ServiceIntegration registration/credential lifecycle administration;
- SuperAdmin/bootstrap operations.

These endpoints:

```text
require actor_type = USER
+ valid Security-issued human access JWT
+ appropriate human admin classification/scope
```

They explicitly reject:

```text
actor_type = SERVICE_INTEGRATION
```

Normal system-to-system business/integration endpoints may accept `SERVICE_INTEGRATION` when the machine JWT audience matches the target module.

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

The targeted global signup/login correction does **not** add Device/Geo columns or a new global device/location table. Existing Device/Geo schema is retained unchanged for future/deferred controls.

### 4.2 USER statuses

Target new-write states:

```text
PENDING | REJECTED | ACTIVE | SUSPENDED | DISABLED
```

Historical legacy values may remain readable during reconciliation, but target APIs do not create new legacy states.

Do not tighten constraints until current data is reconciled.

### 4.3 Global human role definitions — NEW

```text
security.role_definitions
  role_key PK
  role_class        -- OPERATING | ADMIN | TEST
  display_name
  status            -- ACTIVE | INACTIVE
  created_at_utc
  updated_at_utc
```

Seed:

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

`ServiceIntegration` remains a machine actor classification, not a human role assignment.

### 4.4 Platform default role permissions — NEW

```text
security.platform_role_permission_defaults
  role_key
  permission_key
  source_catalog_version nullable
  status
  created_at_utc
  PRIMARY KEY(role_key, permission_key)
```

Seed only approved default bundles.

### 4.5 Tenant role permissions — NEW

```text
security.tenant_role_permissions
  tenant_id
  role_key
  permission_key
  assigned_by_user_id
  assigned_at_utc
  PRIMARY KEY(tenant_id, role_key, permission_key)
```

Rules:

- role is an approved operating role;
- permission exists in canonical catalogue and is ACTIVE when written;
- SuperAdmin updates use atomic replace semantics;
- changing the permission set does not create a new role identity.

### 4.6 Operating-role assignment — NEW

```text
security.user_tenant_operating_roles
  assignment_id uuid PK
  user_id
  tenant_id
  role_key
  status ACTIVE | ENDED
  valid_from_utc nullable
  valid_to_utc nullable
  assigned_by_user_id
  assigned_at_utc
  ended_at_utc nullable
```

Required protections:

- one ACTIVE role per `(user_id, tenant_id)`;
- one ACTIVE `PM` per Tenant;
- only approved operating roles;
- USER must be ACTIVE for new assignment;
- admin/operating exclusivity is checked in the same transaction.

### 4.7 Role-aligned Groups

Preferred Phase-1 implementation is derived Groups rather than independently writable authorization membership.

Logical Groups:

```text
PC
TL
PM
CRM
Executive
```

Group members are the users whose active operating assignment has the corresponding `role_key` in the Tenant.

Do not consult `group_role_assignments` for target authorization.

### 4.8 Administrative-role assignment — NEW

```text
security.user_admin_role_assignments
  assignment_id uuid PK
  user_id
  role_key
  scope_type PLATFORM | TENANT | MODULE
  scope_id nullable
  status ACTIVE | ENDED
  assigned_by_user_id nullable for bootstrap
  assigned_at_utc
  ended_at_utc nullable
```

Scope semantics:

```text
SuperAdmin  -> PLATFORM, scope_id=NULL
TenantAdmin -> TENANT,   scope_id=<tenant UUID>
ModuleAdmin -> MODULE,   scope_id=<module key>
```

Required invariants:

- exactly one ACTIVE SuperAdmin in Phase 1;
- TenantAdmin unique per USER/Tenant;
- ModuleAdmin unique per USER/module;
- administrative roles may coexist with administrative roles;
- any ACTIVE admin role excludes all operating roles globally;
- any ACTIVE operating role excludes all admin roles globally.

### 4.9 TestTenant and TestUser

TestTenant is a **normal Security Tenant** created through the same standard Tenant creation mechanism used for other Tenants.

The existing `PlatformTenantService` generates Tenant IDs using `uuid4()`. TestTenant must use the same system-level behavior. No manual UUID is provided by a user.

Implementation rule:

```text
Security creates TestTenant
  -> standard Tenant service generates UUIDv4
  -> resulting tenant_id is persisted as canonical TestTenant ID
  -> Audit Core and DI use that exact same tenant_id
```

Tenant code/name are system-seeded configuration values and must satisfy the same existing Tenant validation rules as every other Tenant; they are not external user inputs for this implementation.

Exact TestUser Clerk subject:

```text
user_3I7FdD5Pkmydsp23OfjH9hBMxpN
```

Recommended singleton/config relationship:

```text
security.phase1_test_identity
  singleton_id = 1
  user_id FK users UNIQUE
  tenant_id FK tenants UNIQUE
  status ACTIVE | INACTIVE
  created_at_utc
```

Authorization:

```text
TestUser + canonical TestTenant
  -> effective permissions = TestTenant PC bundle
```

TestUser does not receive a production operating/admin role in Phase 1.

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

Deletion request is global and Tenant-independent.

Phase-1 maker may be:

- USER self;
- Executive;
- TenantAdmin;
- ModuleAdmin;
- SuperAdmin.

Final hard delete is SuperAdmin-only.

### 4.11 Deleted USER tombstone — NEW

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

Do not store authentication secrets, JWTs, service credentials, passwords or OTP material.

### 4.12 ServiceIntegration physical model — SIMPLIFIED PHASE 1

Reuse only:

```text
security.security_principals
security.service_integrations
security.principal_credentials
```

Target Phase-1 ServiceIntegration does **not** require new per-service audience-grant tables or per-service permission-grant tables.

It also does not consult:

```text
principal_tenant_scopes
principal_permission_grants
```

for the target machine authorization path.

A registered ACTIVE ServiceIntegration principal with a valid ACTIVE credential may request a machine token for a valid registered Verigence target audience.

The target audience is encoded in the JWT and enforced by the receiving module.

Administrative endpoint access is prevented by endpoint actor-type policy, not by introducing a Phase-1 permission classification.

### 4.13 Permission catalogue classification

No `FUNCTIONAL` / `ADMIN` column or equivalent classification is added in Phase 1.

Current permission catalogue structure remains authoritative.

Formal permission classification/segregation is a Phase-2 item.

---

## 5. Human authorization resolver design

### 5.1 Resolve global USER

Runtime protected-request input:

```text
user_id = global Verigence USER ID from a validated Security-issued human access JWT
```

Rules:

1. global USER exists;
2. retained principal status is ACTIVE where applicable;
3. USER status must be ACTIVE for protected business authorization.

The Clerk external identity mapping is resolved/validated inside Security during onboarding/login and lifecycle operations; Audit Core/DI do not receive or trust Clerk subjects for runtime authorization.

### 5.2 Resolve SuperAdmin

Exact Clerk subject used by Security provisioning/mapping:

```text
user_3I7HFuZZiFC9K2muiweXFRoeoud
```

If USER has the one ACTIVE SuperAdmin assignment:

```text
effective permissions = every ACTIVE registered permission
```

across Security, Audit Core, DI and future registered modules.

No Tenant permission bundle is required for SuperAdmin.

### 5.3 Resolve TenantAdmin

For requested Tenant `T1`:

- USER has ACTIVE `TenantAdmin(T1)` assignment;
- authority is scoped to T1 for normal administration;
- Tenant role-bundle modification remains SuperAdmin-only;
- TenantAdmin may suspend an ACTIVE USER under the confirmed applicable-Tenant rule, with global USER effect;
- deletion request remains a global USER operation.

### 5.4 Resolve ModuleAdmin

- USER has ACTIVE ModuleAdmin assignment for target module;
- module scope applies across Tenants;
- approved ModuleAdmin permissions from the solution design are used;
- operating-user permissions are not inherited automatically.

### 5.5 Resolve TestUser

If the exact TestUser is configured and request Tenant is canonical TestTenant:

```text
effective permissions = TestTenant PC bundle
```

Otherwise protected production-Tenant authorization is denied.

### 5.6 Resolve operating USER

For ordinary operating USER:

1. read one ACTIVE operating role for `(user, tenant)`;
2. read Tenant role bundle for that role key;
3. required canonical permission must be present;
4. Group does not add permissions.

---

## 6. Human USER lifecycle implementation

### 6.1 Security-mediated onboarding through Clerk Backend API

Target sequence:

```text
1. Client submits:
     body = firstName + lastName + email + mobile + password
     X-Onboarding-Key = Verigence Identifier
   Optional Device/Geo request-context headers may also be present but are ignored for
   persistence/access decisions in Phase 1.
2. Security validates the onboarding gate and duplicate identity constraints.
3. Security creates/co-ordinates the Clerk human identity using Clerk Backend APIs.
4. Security initiates the approved email-code verification flow through Clerk.
5. Client submits the email verification code to Security.
6. Security verifies the code through Clerk Backend APIs and validates the expected identity/email relationship.
7. Security records/binds the Clerk subject to the global USER and keeps USER=PENDING.
8. SuperAdmin lists/reviews PENDING USER.
9. SuperAdmin selects ACTIVE or REJECTED.
10. Tenant/role assignment occurs separately.
```

Reuse the existing global onboarding and Security-mediated Clerk email-OTP implementation where compatible. Do **not** replace it with direct client Clerk signup/session JWT or a client-driven authenticated bind flow.

Password/OTP values are transient request secrets and must never be persisted, audited, traced, cached or logged. TOTP/MFA is deferred from the Phase-1 canonical signup/login contract.

### 6.2 Status-transition authority matrix

| Transition/action | Allowed Phase-1 actor |
|---|---|
| `PENDING -> ACTIVE` | SuperAdmin only |
| `PENDING -> REJECTED` | SuperAdmin only |
| `ACTIVE -> SUSPENDED` | Executive or TenantAdmin within applicable Tenant scope; SuperAdmin through all-authority rule |
| `REJECTED -> ACTIVE` | SuperAdmin only |
| `SUSPENDED -> ACTIVE` | SuperAdmin only |
| `DISABLED -> ACTIVE` | SuperAdmin only |
| deletion request `ACTIVE -> DISABLED` | self, Executive, TenantAdmin, ModuleAdmin, SuperAdmin |
| hard DELETE of DISABLED USER | SuperAdmin only |

Suspension status is global even when the authority to initiate it came from an applicable Tenant context.

### 6.3 Clerk synchronization

For `SUSPENDED` or `DISABLED`:

1. establish Security denial state;
2. revoke/terminate Security USER sessions/tokens according to retained session/token capability;
3. terminate/ban Clerk sessions/account state as appropriate for defense in depth;
4. if Clerk synchronization fails, retain local non-ACTIVE state and fail closed.

Reactivation is SuperAdmin-only.

### 6.4 Hard-delete coordinator

Preconditions:

- USER exists;
- USER is DISABLED because of recorded deletion request;
- caller is the one ACTIVE SuperAdmin;
- deletion evidence exists.

Coordinator:

1. lock USER/deletion request;
2. verify preconditions;
3. remove/retire Clerk identity/account as required;
4. create FK-independent tombstone/evidence;
5. end live operating/admin/test assignments;
6. revoke external identity mapping and remaining live Security sessions/tokens;
7. hard-delete live USER/principal rows in safe order;
8. record completion outcome;
9. release email for reuse;
10. retain approved tombstone/deletion reference for 21 days.

---

## 7. Role and Group implementation

### 7.1 No Tenant-created operating roles

Retire active use of arbitrary Tenant role creation for PC/TL/PM/CRM/Executive.

Global role definitions are fixed classifications.

### 7.2 Operating role set/replace

```text
set_operating_role(user, tenant, role_key, actor)
```

Transaction:

1. validate USER ACTIVE;
2. validate Tenant ACTIVE;
3. validate approved operating role;
4. reject if USER has any admin assignment;
5. for PM, lock/check uniqueness;
6. end current `(user, tenant)` operating assignment if different;
7. insert new assignment;
8. role-aligned Group view changes automatically;
9. audit before/after;
10. commit atomically.

Assigning the same role again is idempotent.

### 7.3 Group implementation

Read-only logical groups:

```text
PC
TL
PM
CRM
Executive
```

Group APIs query operating-role assignments.

Do not use arbitrary Group role grants or Group-derived permission union in target authorization.

---

## 8. Administrative-role implementation

### 8.1 SuperAdmin

Exactly one ACTIVE SuperAdmin in Phase 1.

Exact Clerk subject:

```text
user_3I7HFuZZiFC9K2muiweXFRoeoud
```

Reuse current initial-SuperAdmin provisioning concepts that bind immutable Clerk subject and prevent conflicting active SuperAdmin.

SuperAdmin has every ACTIVE registered permission and all Phase-1 platform administration authority.

### 8.2 TenantAdmin

Scope:

```text
one Tenant across modules
```

TenantAdmin manages approved Tenant-level administration and operating-role assignments for its Tenant.

TenantAdmin cannot change the Tenant role->permission definition in Phase 1.

TenantAdmin can initiate global suspension under the confirmed applicable-Tenant rule.

### 8.3 ModuleAdmin

Scope:

```text
one module across all Tenants
```

Use only approved module-administration permissions already defined in the solution design/current canonical module catalogues.

### 8.4 Admin/operating exclusivity

Admin assignment and operating-role assignment use the same invariant checker inside the write transaction.

### 8.5 Machine exclusion from administrative APIs

Every administrative/control-plane route must verify human actor type from a valid Security-issued human access JWT before administrative authorization.

`SERVICE_INTEGRATION` is rejected even if its JWT is otherwise valid for the Security/module audience.

---

## 9. Permission catalogue and default seed implementation

### 9.1 Module permission discovery

Retain the current catalogue and expose:

```text
GET /security/v1/platform/modules
GET /security/v1/platform/modules/{moduleKey}
GET /security/v1/platform/modules/{moduleKey}/permissions
```

Permission discovery reads the existing Security catalogue; no second permission store is created.

### 9.2 Platform role defaults

Seed the exact approved cross-module PC/TL/PM/CRM defaults already recorded in `SECURITY_SOLUTION_DESIGN_v2.0.md`.

Do not silently drop a missing/retired permission. Surface catalogue mismatch before migration is approved.

Executive default remains:

- Audit Core: approved read permissions plus normal non-destructive update/write privileges;
- DI: read-only;
- no DI configuration administration;
- no stronger destructive/admin capabilities unless separately approved.

The concrete Executive list must be generated from existing registered keys and reviewed before seed migration.

### 9.3 Tenant creation seeding

```text
create Tenant
  -> copy PC default bundle
  -> copy TL default bundle
  -> copy PM default bundle
  -> copy CRM default bundle
  -> copy Executive default bundle
```

### 9.4 Tenant override

Only SuperAdmin may atomically replace a Tenant's role permission bundle.

### 9.5 Permission classification deferred

No new permission class is introduced in Phase 1.

`FUNCTIONAL` versus `ADMIN` segregation is explicitly deferred to Phase 2.

---

## 10. TestUser / TestTenant implementation

Exact TestUser Clerk subject:

```text
user_3I7FdD5Pkmydsp23OfjH9hBMxpN
```

Implementation:

1. create TestTenant through the existing standard Tenant creation service;
2. let the service generate the Tenant UUID using normal UUIDv4 behavior;
3. persist that generated UUID as canonical TestTenant ID;
4. seed normal Tenant defaults;
5. bind the exact TestUser Clerk subject to one global Security USER if not already mapped;
6. configure TestUser -> TestTenant;
7. resolve TestUser permissions as TestTenant PC bundle;
8. expose the canonical generated TestTenant ID for Audit Core and DI so all modules use the same Tenant identity.

No user-supplied TestTenant UUID is required.

---

## 11. ServiceIntegration implementation design

### 11.1 Reuse base

Reuse:

- machine principal `actor_type='SERVICE_INTEGRATION'`;
- `service_integrations`;
- `principal_credentials`;
- existing Argon2 secret hashing/verification;
- Security RSA signing key;
- Security JWKS endpoint;
- current Basic/client-credential parsing patterns where useful;
- existing service audit patterns.

### 11.2 Platform-global service identity

Target ServiceIntegration has no Tenant authorization dependency.

Do not consult `principal_tenant_scopes` or Tenant-scoped `principal_permission_grants` in the new machine path.

### 11.3 Canonical service-token endpoint

```text
POST /security/v1/service/token
```

This is the only target Phase-1 external contract for new machine-token issuance.

Existing:

```text
POST /oauth/token
```

is deprecated. Its implementation may be reused internally while the route itself is removed from the active contract after clients migrate.

### 11.4 Request contract

Conceptually:

```text
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

audience=<registered target module/security audience>
```

No Tenant ID is required.

No per-service functional scope list is required in Phase 1.

### 11.5 Token TTL

```text
4 hours
```

No refresh token is required. The service obtains a new token when needed.

### 11.6 Machine JWT claim shape

Required target claims:

```text
iss
sub = registered service identity
actor_type = SERVICE_INTEGRATION
aud = requested target module/security audience
iat
exp = iat + 4 hours
jti
```

No required machine claims for:

- tenant_id;
- human roles;
- device_id;
- location_id;
- human authorization version;
- per-service functional permission list.

### 11.7 Audience enforcement

Security only issues a token when the requested audience corresponds to a valid registered Verigence module/security audience.

Receiving module validates exact expected audience locally.

Example:

```text
aud = di
```

is valid for DI and must be rejected by Security/Audit Core as the wrong target audience.

### 11.8 Broad machine access rule

A registered ACTIVE ServiceIntegration with a valid credential may call normal non-administrative integration/business endpoints of the target module using a correctly audience-bound machine JWT.

Phase 1 does not maintain service-specific functional permission grants.

### 11.9 Administrative endpoint exclusion

Administrative endpoints are human-admin-only.

ServiceIntegration must be rejected from operations including, but not limited to:

- USER approval/rejection/suspension/reactivation/deletion administration;
- Tenant creation/lifecycle changes;
- role/admin assignment;
- Tenant permission-bundle changes;
- module/security administration;
- service-client credential administration;
- SuperAdmin/bootstrap administration.

This is enforced through allowed actor type at the endpoint/policy layer.

### 11.10 Authorization-check caller

Audit Core/DI/Web may call:

```text
POST /security/v1/authorization/check
```

using a valid ServiceIntegration JWT with:

```text
actor_type = SERVICE_INTEGRATION
aud = security
```

No new `security.authorization.check` permission key is created in Phase 1.

The machine identity establishes that the human authorization context came from a trusted registered backend; Security then evaluates the human USER's permission using the global USER ID derived by the caller from a validated Security human JWT.

### 11.11 External/unregistered systems

External callers cannot obtain a valid machine token unless explicitly provisioned into the Security service registry with a valid credential.

DI/Audit Core/Security reject:

- missing token;
- fake/untrusted signature;
- expired token;
- wrong issuer;
- wrong audience;
- actor type other than accepted type for the endpoint;
- unregistered/inactive service identity where live service-state validation is performed.

---

## 12. Target API/OpenAPI design

### 12.1 Human authentication APIs and protected Security API authentication

Canonical human login:

```text
POST /security/v1/auth/login
```

Request body:

```json
{
  "identifier": "employee@example.com",
  "password": "<transient secret>"
}
```

Not part of the canonical login request:

```text
tenantId
deviceId body field
geo body field
totpCode
```

Optional Device ID / Geo request-context headers may be sent by clients. The active Phase-1 login route does not require, persist or evaluate them. Their exact future interpretation is intentionally deferred.

Security verifies credentials through Clerk Backend APIs, resolves the Clerk subject to the global USER, requires an ACTIVE Security USER/principal/identity mapping, and returns a Security-issued human access token response. The human token is global identity/session evidence and does not embed Tenant authorization as authority.

The targeted correction reuses the currently configured Security human/admin access-token lifetime setting rather than inventing a new TTL value. If the required configured lifetime is unavailable, token issuance fails closed. Configuration renaming/cleanup is separate from the Phase-1 contract correction.

Protected human Security APIs then use:

```text
Authorization: Bearer <Security-issued human access JWT>
```

Dependency:

```text
validate Security human JWT
 -> resolve global USER from trusted token identity
 -> validate USER status
 -> require human actor
 -> evaluate admin/operating/test permission and scope
```

No protected Verigence module requires a Clerk JWT or Clerk key.

### 12.2 USER APIs

```text
GET /security/v1/platform/users
GET /security/v1/platform/users/{userId}
PATCH /security/v1/users/{userId}/status
DELETE /security/v1/platform/users/{userId}
```

Status API enforces transition-specific authority, not only a generic permission.

Hard DELETE is SuperAdmin-only.

### 12.3 Tenant APIs

Reuse logical surface:

```text
POST  /security/v1/platform/tenants
GET   /security/v1/platform/tenants
GET   /security/v1/platform/tenants/{tenantId}
PATCH /security/v1/platform/tenants/{tenantId}
POST  /security/v1/platform/tenants/{tenantId}/activate
```

### 12.4 Role APIs

```text
GET /security/v1/roles
PUT /security/v1/tenants/{tenantId}/users/{userId}/operating-role
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

Set/replace semantics only.

### 12.5 Group APIs

```text
GET /security/v1/tenants/{tenantId}/groups
GET /security/v1/tenants/{tenantId}/groups/{roleKey}
GET /security/v1/tenants/{tenantId}/groups/{roleKey}/users
```

No independent Group permission or Group role mutation API in the target model.

### 12.6 Admin-role APIs

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

### 12.7 Permission/default APIs

```text
GET /security/v1/platform/modules
GET /security/v1/platform/modules/{moduleKey}
GET /security/v1/platform/modules/{moduleKey}/permissions
PUT /security/v1/platform/modules/{moduleKey}/catalog

GET /security/v1/platform/role-defaults/{roleKey}
GET /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
PUT /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
```

Tenant bundle PUT is SuperAdmin-only.

### 12.8 Runtime human authorization API

```text
POST /security/v1/authorization/check
Authorization: Bearer <ServiceIntegration JWT, aud=security>
```

Request:

```json
{
  "userId": "<global USER ID extracted from a Security human JWT already validated by caller>",
  "tenantId": "<tenant UUID or null for supported platform context>",
  "permissionKey": "<registered human permission>"
}
```

Security:

1. authenticates ServiceIntegration caller;
2. validates audience `security`;
3. resolves the supplied global USER ID;
4. requires ACTIVE human USER;
5. evaluates current human classification/scope/Tenant bundle;
6. returns allow/deny.

No separate machine permission key is required to invoke this endpoint in Phase 1.

### 12.9 Service token API

```text
POST /security/v1/service/token
Authorization: Basic <client_id:client_secret>
Content-Type: application/x-www-form-urlencoded

audience=<target>
```

Response includes the signed bearer token and 4-hour expiry metadata.

`/oauth/token` is deprecated from the target contract.

### 12.10 Onboarding/email verification APIs

Target Security-only Clerk integration keeps the Verigence-facing onboarding facade:

```text
POST /security/v1/onboarding/users
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
POST /security/v1/auth/precheck    # optional existing UX gate
```

Canonical signup request:

```text
body: firstName + lastName + email + mobile + password
header: X-Onboarding-Key = user-facing Verigence Identifier
optional Device ID / Geo request-context headers: accepted by the HTTP boundary but not persisted/evaluated in Phase 1
```

There is no target client-driven Clerk session bind endpoint.

---

## 13. Endpoint caller policy matrix

| Capability | Human USER | ServiceIntegration | Main Phase-1 rule |
|---|---:|---:|---|
| Human onboarding/email verification/login | Yes | No | Verigence client -> Security -> Clerk Backend API only |
| Approve/reject PENDING USER | SuperAdmin | No | human admin only |
| Suspend USER | Executive/TenantAdmin/SuperAdmin | No | human admin/Executive rule |
| Reactivate USER | SuperAdmin | No | human admin only |
| Request USER deletion | approved human makers | No | global USER operation |
| Final hard delete | SuperAdmin | No | human admin only |
| Create/update Tenant | approved human admin | No | administrative |
| Assign operating/admin role | approved human admin | No | administrative |
| Change Tenant role bundle | SuperAdmin | No | administrative |
| Module permission catalogue administration | approved human admin | No | administrative |
| Service registry/credential administration | human admin; SuperAdmin necessarily authorized | No | administrative |
| `/authorization/check` | Security uses resolver in-process | Yes, aud=security | trusted backend path |
| Normal Audit Core business integration API | as human permission allows | Yes, aud=audit-core | non-admin endpoint |
| Normal DI integration API | as human permission allows | Yes, aud=di | non-admin endpoint |

Phase 1 does not require a separate machine permission key for `/authorization/check` and does not maintain per-service functional permission matrices.

---

## 14. Migration and reconciliation plan

Historical migrations remain unchanged.

### 14.1 Additive sequence

1. add target role-definition/default/Tenant-bundle tables;
2. add operating-role assignment table and indexes;
3. add scoped admin-role assignment structures;
4. add TestUser/TestTenant configuration relation;
5. add deletion request and tombstone structures;
6. adjust USER status constraint after reconciliation;
7. seed fixed global role definitions;
8. seed approved default role bundles;
9. migrate/reconcile active legacy role data;
10. migrate the confirmed SuperAdmin identity to canonical target admin assignment;
11. create TestTenant through standard Tenant service and bind confirmed TestUser;
12. reconcile existing machine principals/credentials as platform-global ServiceIntegration identities;
13. implement new `/security/v1/service/token` using reused credential/signing internals;
14. implement synchronous `/authorization/check` using global USER identity derived from validated Security human tokens;
15. retain/align the canonical `/security/v1/auth/login` Security-only Clerk Backend authentication facade and Security human token issuance without Tenant/device/Geo/TOTP coupling;
16. cut target RBAC reads to the new role model;
17. deprecate `/oauth/token` and retire duplicate/legacy human authentication/token routes such as separate PlatformAdmin token/login/bootstrap paths after dependent callers migrate; do not retire canonical `/security/v1/auth/login`;
18. leave historical/deferred tables intact.

The global login/onboarding correction does not require a Device/Geo schema migration.

### 14.2 Mandatory reconciliation report

Before role cutover identify:

- users with multiple direct roles in a Tenant;
- Group-derived extra roles;
- admin + operating mixtures;
- Tenants with more than one candidate PM;
- custom Tenant roles with no approved target-role mapping;
- permissions available only via arbitrary Group-role chains;
- arbitrary Groups not equivalent to role-aligned Group;
- legacy USER states requiring explicit mapping;
- conflicting SuperAdmin assignments;
- machine principals/credentials that need conversion from Tenant-scoped behavior to platform-global ServiceIntegration.

Do not auto-pick winners for ambiguous data.

---

## 15. Device/Geo/Schedule/VPN deferral

Keep:

- schema;
- migrations;
- feature code;
- administration code;
- independent feature tests.

Do not require these controls in:

- canonical Security human login/token issuance;
- Security-mediated employee signup/email verification;
- Security in-process human authorization;
- `/authorization/check`;
- operating/admin/test permission resolution.

Client Device ID / Geo request-context headers may still be sent on signup/login. Phase 1 does not persist or evaluate them. Do not create a new schema merely to retain unused request context.

Future Phase 2 can reintroduce selected controls without redesigning global identity/RBAC.

---

## 16. Code-level implementation work breakdown

No code is authorized by this blueprint yet.

### Step 1 — Additive target schema

**Reuse:** migration framework/current schema.  
**Add:** role definitions, bundles, scoped admin roles, deletion/tombstone, test identity relation.  
**Do not add:** service permission/audience grant tables for Phase 1.  
**Do not add for login/onboarding correction:** Device/Geo persistence.  
**Tests:** constraints, indexes, migration-up fixtures.

### Step 2 — Security-only Clerk human authentication + Security human token

**Reuse:** `services/clerk_credentials.py`, existing `/security/v1/auth/login` flow, Security token signing/JWKS primitives, external identity mapping.  
**Modify request:** `identifier + password` only; remove `tenantId`, mandatory body `deviceId`, mandatory body Geo and `totpCode`.  
**Modify runtime:** resolve Clerk subject -> global Security USER, require ACTIVE USER/principal/identity, issue an identity-oriented Security human JWT without invoking Tenant/device/Geo/schedule/VPN authorization.  
**Optional request context:** Device ID / Geo headers may be present but are not persisted or evaluated.  
**Retire active use:** direct Clerk-session-JWT route dependencies and separate PlatformAdmin login/token path.  
**Tests:** successful/failed Clerk-backed password verification, TOTP not required, no secret persistence/logging, no Tenant input, no Device/Geo requirement, correct global USER binding, non-ACTIVE USER denial, valid/invalid Security human JWT validation.

### Step 3 — USER lifecycle and onboarding

**Reuse:** global onboarding/user service and existing Security-mediated Clerk email OTP integration.  
**Retain request:** firstName/lastName/email/mobile/password + `X-Onboarding-Key` (Verigence Identifier).  
**Modify:** PENDING/REJECTED, transition authority and lifecycle policy; do not introduce direct client Clerk signup/bind or Device/Geo persistence.  
**Tests:** onboarding gate, duplicate handling, Clerk creation/verification failures, resend/verify flow, PENDING after verification, all allowed/denied lifecycle transitions.

### Step 4 — Deletion coordinator

**New:** deletion request/tombstone/coordinator.  
**Reuse:** Clerk lifecycle adapter, Security token/session revocation and Security audit patterns.  
**Tests:** makers, global DISABLED, hard-delete SuperAdmin-only, 21-day retention.

### Step 5 — Operating roles

**Replace:** additive Tenant-role assignment runtime.  
**Add:** role-key assignment service.  
**Tests:** one role/Tenant, cross-Tenant variation, one PM/Tenant, idempotent replace.

### Step 6 — Role-aligned Groups

**Modify:** Group reads to project operating assignments.  
**Retire active:** arbitrary Group role grants.  
**Tests:** role change changes Group membership; Group cannot add authorization.

### Step 7 — Admin assignments

**Reuse:** initial SuperAdmin provisioning concepts.  
**Add:** scoped TenantAdmin/ModuleAdmin persistence/resolver.  
**Tests:** scope, stacking, admin/operating exclusivity, exactly one SuperAdmin.

### Step 8 — Defaults and Tenant bundles

**Reuse:** permission/module catalogue.  
**Add:** platform defaults and Tenant copies.  
**Tests:** approved PC/TL/PM/CRM defaults, Executive generated list, TestUser PC inheritance, SuperAdmin all ACTIVE permissions.

### Step 9 — TestTenant/TestUser bootstrap

**Use exact TestUser:** `user_3I7FdD5Pkmydsp23OfjH9hBMxpN`.  
**Create TestTenant:** standard `PlatformTenantService`, generated UUIDv4.  
**Tests:** canonical ID, TestUser only in TestTenant, PC-equivalent permissions.

### Step 10 — ServiceIntegration token flow

**Reuse:** client credential verification, Argon2 hashing, RSA signing/JWKS.  
**New canonical route:** `/security/v1/service/token`.  
**Modify:** machine claim shape becomes platform-global/audience-bound; no Tenant or per-service functional grant.  
**TTL:** 4 hours.  
**Deprecate:** `/oauth/token`.  
**Tests:** valid/invalid credential, expiry, wrong audience, fake token, external unregistered client.

### Step 11 — Authorization check

**Add:** `/security/v1/authorization/check`.  
**Caller:** ServiceIntegration with `aud=security`.  
**Human context:** global USER ID derived from a validated Security human JWT, never an arbitrary client-supplied identity.  
**No new machine permission key.**  
**Tests:** valid backend/human allow, inactive USER deny, arbitrary browser deny, wrong audience deny.

### Step 12 — Human-admin endpoint gating

**Modify:** all administrative Security routes to require a valid Security-issued human access JWT and appropriate admin scope.  
**Explicitly reject:** ServiceIntegration.  
**Tests:** machine token cannot create Tenant, approve USER, assign role, change role bundle or manage service credentials.

### Step 13 — Retire only conflicting legacy human and OAuth contracts

Retire active use of:

- direct Clerk session JWT as the Verigence client/resource-server human token;
- separate PlatformAdmin Security JWT/login/bootstrap path;
- legacy/deprecated human `access_sessions` bridge where it duplicates the canonical login/session model;
- USER token exchange;
- old `/oauth/token` machine endpoint after migration.

Retain and align:

- canonical human `POST /security/v1/auth/login`;
- Security-issued human access JWT/session model;
- Security-only Clerk Backend integration for human creation/authentication;
- Security signing/JWKS required by downstream validation.

Keep historical code/migrations until cleanup is separately approved.

---

## 17. Test strategy

### 17.1 Human authentication

- Web/Mobile/Audit Core/DI contain no direct Clerk authentication dependency in the Security contract;
- Security successfully authenticates valid human identifier/password through Clerk Backend API;
- invalid human credentials are denied;
- `/security/v1/auth/login` accepts no `tenantId` requirement;
- Device ID / Geo are not mandatory inputs and optional request-context headers do not change the authentication result;
- TOTP/MFA is not required in Phase 1;
- password/OTP values are not persisted, audited, traced, cached or logged;
- successful login resolves the correct Clerk subject -> global USER mapping;
- non-ACTIVE USER cannot obtain/use protected Verigence access merely because Clerk credential verification succeeded;
- valid Security-issued human JWT is accepted by protected Security/resource-server validation;
- expired/invalid Security human JWT is denied;
- invalid issuer/signature is denied;
- DEV mock remains environment-limited.

### 17.2 USER lifecycle

- PENDING/REJECTED/SUSPENDED/DISABLED denied protected access;
- only SuperAdmin approves/rejects PENDING;
- Executive suspension scope enforced;
- TenantAdmin suspension scope enforced;
- suspension effect global;
- only SuperAdmin reactivates.

### 17.3 Role/admin invariants

- one operating role/User/Tenant;
- different operating roles across Tenants;
- one PM/Tenant;
- admin and operating mutually exclusive globally;
- admin roles may stack;
- one active SuperAdmin.

### 17.4 Groups

- logical Group members match active operating assignments;
- role replace changes Group membership;
- no arbitrary Group permission inheritance.

### 17.5 Permission bundles

- exact approved PC/TL/PM/CRM defaults;
- Executive generated list reviewed against registered keys;
- Tenant copy created;
- SuperAdmin override affects only intended Tenant;
- invalid/retired permission cannot be added;
- SuperAdmin gets newly registered ACTIVE permissions.

### 17.6 TestUser/TestTenant

- exact Clerk TestUser subject maps correctly;
- TestTenant uses normal UUIDv4 Tenant ID generation;
- same canonical TestTenant ID is exposed to dependent modules;
- TestUser effective permissions equal TestTenant PC bundle;
- TestUser denied in production Tenant context.

### 17.7 Deletion

- approved makers -> DISABLED;
- final hard delete non-SuperAdmin denied;
- same SuperAdmin maker/checker allowed;
- Clerk dependency failure does not report false success;
- live USER removed on successful delete;
- email reusable;
- tombstone independent of USER FK;
- retention deadline +21 days;
- no secrets retained.

### 17.8 ServiceIntegration

- exact 4-hour token lifetime;
- valid registered credential obtains token;
- unknown client denied;
- wrong secret denied;
- inactive/revoked credential denied;
- token has `actor_type=SERVICE_INTEGRATION`;
- target audience required;
- wrong audience rejected by target;
- fake/untrusted signature denied;
- external unregistered caller cannot get token;
- no Tenant ID required;
- no per-service functional permission grant required;
- normal non-admin machine endpoint allowed when audience is correct;
- administrative endpoint rejects valid ServiceIntegration token.

### 17.9 Authorization check

- valid backend `aud=security` + validated Security-human-token USER + active USER + permission -> allow;
- inactive human -> deny;
- arbitrary browser without machine identity -> deny;
- arbitrary client-supplied USER identity is not trusted;
- wrong audience -> deny;
- invalid human permission -> deny/error;
- role permission absent -> deny;
- SuperAdmin human -> allow for any ACTIVE registered permission;
- TenantAdmin/ModuleAdmin scope enforced;
- Security itself uses resolver in-process.

### 17.10 Deferred controls

Regression tests prove Device/Geo/Schedule/VPN code remains available while target authorization does not require those inputs and global signup/login does not persist them.

---

## 18. Operational/failure rules

1. Security authorization unavailable -> protected backend human operation fails closed.
2. Clerk Backend credential/user operation failure -> Security fails the corresponding onboarding/login operation and does not report false success.
3. Security human JWT invalid/expired/untrusted -> protected human request denied before authorization.
4. Machine token invalid/wrong audience -> deny before target operation.
5. ServiceIntegration never bypasses human-admin-only endpoint actor-type checks.
6. USER non-ACTIVE status affects the next synchronous authorization decision immediately even if a human JWT remains cryptographically valid.
7. Tenant role-bundle update affects subsequent decisions without human token reissue.
8. Audit Core remains responsible for Dealer/Outlet business scope.
9. DI remains outside onboarding and has no Clerk integration.
10. No plaintext human credential, OTP, service credential or JWT is logged.
11. TestTenant uses one canonical generated Security Tenant ID across modules.
12. Missing Device/Geo request context must not cause signup/login denial in Phase 1.
13. Missing configured Security human-token lifetime/signing material fails token issuance closed rather than inventing a value.

---

## 19. Explicitly retired/deferred behavior

### Retire from active Phase 1

- direct Web/Mobile Clerk SDK/API/session-JWT authentication path;
- direct Clerk JWT validation in Audit Core/DI/Web BFF;
- separate PlatformAdmin Security JWT/login/bootstrap authentication path;
- duplicate/legacy human access-session bridge that is not the canonical Security human login/session path;
- USER token exchange;
- arbitrary Tenant operating-role creation;
- additive/multiple operating roles;
- arbitrary Group->Role permission union;
- Tenant membership as a human authorization prerequisite;
- Tenant-scoped ServiceIntegration authorization grants;
- per-service functional permission matrices;
- `/oauth/token` as target machine-token contract.

### Keep but defer

- Device mandatory gate;
- Geo/geofence mandatory gate;
- Schedule mandatory gate;
- VPN/network-risk mandatory gate;
- Device/Geo persistence or binding to the global signup/login transaction;
- MFA/TOTP;
- any new human-token authorization cache/projection design beyond the retained Security session/token primitives;
- mTLS;
- distributed authorization projection/cache;
- additional SuperAdmins;
- Dealer/Outlet staffing/cardinality rules;
- arbitrary custom Groups;
- permission `FUNCTIONAL`/`ADMIN` classification.

---

## 20. Remaining implementation inputs

The following are now **resolved**:

```text
SuperAdmin Clerk subject
= user_3I7HFuZZiFC9K2muiweXFRoeoud

TestUser Clerk subject
= user_3I7FdD5Pkmydsp23OfjH9hBMxpN

TestTenant tenant_id
= generated by standard Security Tenant creation using UUIDv4

Human Clerk integration boundary
= Security only; no direct Web/Mobile/Web BFF/Audit Core/DI Clerk integration

Canonical signup input
= firstName + lastName + email + mobile + password
  X-Onboarding-Key carries the user-facing Verigence Identifier

Canonical human login endpoint
= POST /security/v1/auth/login

Canonical human login request
= identifier + password; no tenantId; no mandatory Device/Geo; no TOTP/MFA

Device/Geo signup/login context
= optional client request headers only; not persisted/evaluated in Phase 1; no DB migration

Human token issuer
= Verigence Security after Clerk-backed authentication

ServiceIntegration token TTL
= 4 hours

Machine token endpoint
= POST /security/v1/service/token

Legacy machine endpoint
= /oauth/token deprecated

ServiceIntegration functional grants
= no per-service functional permission matrix in Phase 1

Authorization-check machine permission key
= no new permission key; valid ServiceIntegration + aud=security is sufficient

Administrative endpoint rule
= Security-authenticated human admin only; SERVICE_INTEGRATION rejected

Permission classification
= unchanged in Phase 1; formal segregation deferred to Phase 2
```

Still implementation-level but not a business/design input from the user:

1. system-seeded TestTenant `tenantCode` and `tenantName` values must use the existing Tenant validation/convention; no user-supplied UUID is required;
2. service credential rotation/expiry operations should reuse existing credential lifecycle capability and can be finalized as an operational setting without altering the architecture;
3. concrete Executive default permission list must be generated from the already registered Audit Core/DI keys and reviewed before the seed migration is committed;
4. current `dev` data must be reconciled before deterministic role migration;
5. the concrete configured human access-token/session lifetime and revocation/version behavior must be taken from retained Security configuration/capability and must not be replaced with an invented new TTL during this targeted login correction.

No implementation should invent new business permissions or authentication semantics to resolve these items.

---

## 21. Recommended implementation order

```text
1. Approve this implementation blueprint
2. Run current dev reconciliation report
3. Add additive target schema
4. Align Security-only Clerk Backend onboarding/login + canonical Security human JWT/session boundary
5. Implement global USER lifecycle and transition policy
6. Implement deletion request/hard-delete/tombstone
7. Implement global role definitions + one operating role/User/Tenant
8. Implement role-aligned Group reads
9. Implement scoped admin assignments
10. Bind confirmed single SuperAdmin identity and all-ACTIVE invariant
11. Implement platform defaults + Tenant role bundles
12. Create canonical TestTenant through standard Tenant service
13. Bind confirmed TestUser and PC-equivalent TestTenant behavior
14. Refactor machine JWT claim/signing model for platform-global ServiceIntegration
15. Implement POST /security/v1/service/token with 4-hour TTL
16. Implement POST /security/v1/authorization/check using USER identity from validated Security human JWTs
17. Add human-admin-only actor gate to administrative endpoints
18. Rewire human Security admin/Tenant/module APIs to the canonical Security human JWT + in-process AuthZ
19. Migrate clean legacy role/admin records into target structures
20. Cut target runtime authorization to new model
21. Deprecate /oauth/token and retire only duplicate/incorrect human authentication routes (direct-Clerk assumptions, separate PlatformAdmin login/bootstrap, legacy access-session bridge); retain /security/v1/auth/login
22. Run Security end-to-end tests
23. Only after Security is proven, align Audit Core/DI contracts in their own separately approved changes without introducing Clerk integration outside Security
```

---

## 22. Definition of implementation-ready

Security v2 Phase-1 is ready for coding when:

- this implementation blueprint is approved;
- current `dev` data reconciliation is understood sufficiently for deterministic migrations;
- concrete Executive default key list is reviewed from existing registered permissions;
- system TestTenant seed values are selected using the existing Tenant format during implementation preparation.

The following no longer block implementation planning:

- SuperAdmin identity;
- TestUser identity;
- TestTenant UUID selection;
- Security-only Clerk integration boundary;
- canonical signup and login request fields;
- no-Tenant login semantics;
- optional/non-persisted Device/Geo request context;
- Phase-1 no-MFA/TOTP login rule;
- canonical human login endpoint and Security human-token ownership;
- ServiceIntegration TTL;
- service-token endpoint naming;
- authorization-check machine permission naming;
- service-specific functional grant matrix;
- Phase-1 permission classification.

Security v2 Phase-1 is implementation-complete only when:

- Web/Mobile, Web BFF, Audit Core and DI have no direct Clerk authentication dependency in the Security contract;
- Security alone performs Clerk Backend user creation/email verification/credential authentication;
- `/security/v1/onboarding/users` keeps the approved firstName/lastName/email/mobile/password + `X-Onboarding-Key` contract;
- `/security/v1/auth/login` is the canonical active human login path for all human classifications and requires only identifier/password;
- login has no Tenant requirement and no mandatory Device/Geo/TOTP input;
- optional Device/Geo request context does not get persisted or affect Phase-1 signup/login allow/deny;
- Security issues the active Verigence human access JWT/session after successful Clerk-backed authentication;
- downstream protected human resource servers validate Security human JWTs, not Clerk JWTs;
- synchronous Security human authorization enforces the target role/admin/test model and does not trust embedded human permission claims as the source of truth;
- one operating role/User/Tenant and one PM/Tenant are enforced;
- role-aligned Groups are non-additive;
- exact SuperAdmin identity is active and has every ACTIVE registered permission;
- TenantAdmin and ModuleAdmin scope tests pass;
- PENDING approval/rejection is SuperAdmin-only;
- Executive/TenantAdmin suspension policy passes;
- deletion and 21-day retention tests pass;
- exact TestUser/TestTenant behavior passes;
- ServiceIntegration is platform-global;
- machine tokens use `/security/v1/service/token`, have 4-hour TTL and correct target audience;
- normal system-to-system calls work without per-service functional permission matrices;
- administrative endpoints reject `SERVICE_INTEGRATION`;
- unregistered/external systems cannot obtain or use a valid target machine token;
- Device/Geo/Schedule/VPN capabilities remain available but are not mandatory Phase-1 authorization gates;
- legacy Tenant role/Group state no longer contributes to the target runtime authorization result;
- duplicate/incorrect human authentication paths no longer participate in runtime, while the canonical Security human login/token boundary remains active.
