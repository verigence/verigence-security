# Verigence Security Admin Control Plane and Cross-Module Authorization Design v1.4

**Status:** APPROVED FOR IMPLEMENTATION  
**Date:** 2026-08-13  
**Repository:** `verigence/verigence-security`  
**Security baseline reviewed:** `dev@ca3e0cd08ebb12040eefa911dfc147e3643e09ac`  
**DI baseline reviewed:** `verigence/verigence-di dev@caf0dfab8d80357ab76568538b8f73f2d2e05fc0`  
**Supersedes:** no Security v1.3 normative artifact; this is a versioned v1.4 control-plane extension.

---

## 1. Purpose and authority

This document is the implementation authority for the new Verigence Security Admin Control Plane.

It governs:

- Platform administration and bootstrap;
- direct Tenant creation;
- standard Platform and Tenant administrator roles;
- the canonical `security.*` administrator permission catalogue;
- Tenant groups;
- cross-module permission registration;
- module role templates;
- Tenant roles and effective RBAC;
- team-member invitation and human acceptance;
- privileged-access maker-checker;
- Admin API routes;
- v1.4 database extensions;
- Security JWT/module integration rules;
- Document Intelligence (DI) alignment;
- implementation sequence and acceptance tests.

This document does **not** silently modify Security v1.3. It explicitly versions new control-plane decisions.

Where this document says an item is deferred or blocked, implementation MUST NOT infer the missing behavior.

---

## 2. Provenance: what is fact versus new v1.4 design

### 2.1 Existing Security v1.3 facts retained unchanged

The existing Security schema already establishes:

- Tenant lifecycle values:
  `CONFIGURING`, `ACTIVE`, `SUSPENDED`, `OFFBOARDING`, `OFFBOARDED`;
- Security Principal actor types:
  `USER`, `SYSTEM`, `SERVICE_INTEGRATION`;
- USER status including `INVITED` and `ACTIVE`;
- Tenant membership status including `PENDING` and `ACTIVE`;
- global permission records with `module_key`, `resource_key`, `action_key`;
- Tenant-scoped roles;
- role-permission grants;
- direct user-role assignments;
- Tenant-scoped machine-principal grants;
- Tenant locations and schedules;
- USER location/schedule assignments;
- Security JWT issuance and effective-permission resolution.

The immutable migration remains:

```text
migrations/0001_security_baseline_v1.3.sql
```

It MUST remain byte-identical.

### 2.2 Existing Phase 5 implementation retained

The current Security code already implements and Neon-validates internal administration for:

- Tenant Security Policy;
- Security Retention Policy;
- Tenant locations;
- schedules/windows;
- USER Security-side onboarding records;
- external identity mapping;
- Tenant memberships;
- user-location/schedule assignments;
- canonical permissions;
- Tenant roles;
- role-permission grants;
- direct user-role assignments;
- fail-closed activation-readiness foundation.

v1.4 exposes and extends this model. It does not create a parallel administration store.

### 2.3 Existing DI implementation facts retained

The reviewed DI code already:

- verifies Security-issued JWTs through Security JWKS;
- expects issuer `verigence-security`;
- consumes `tenant_id`, `actor_type`, `roles[]`, `permissions[]`, `device_id`,
  `access_session_id`, and `location_id`;
- treats `permissions[]` as authoritative;
- treats role names as informational/backward-compatible;
- has `require_permission()` and `require_tenant_permission()`;
- defines 28 canonical `di.*` permissions;
- defines eight current role bundles for defaults/mock behavior.

These facts are used as the starting point for DI integration. They are not reconstructed from memory.

---

## 3. Non-negotiable authorization principles

### RULE-AUTH-001 — Security is the authorization authority

Security owns:

- identities and Security Principals;
- Tenant memberships;
- Platform administrators;
- module catalogue;
- canonical permissions;
- Tenant roles;
- Tenant groups;
- role/group/user assignments;
- effective permissions;
- access tokens.

A business module MUST NOT maintain a second authoritative user-role assignment system.

### RULE-AUTH-002 — Modules own capabilities and templates

A module such as DI or WPM owns:

- the operations it exposes;
- the canonical permissions required by those operations;
- optional standard role templates containing only that module's permissions.

A module does not own the runtime Tenant role assigned to a user.

### RULE-AUTH-003 — Permissions are the runtime contract

Modules authorize by permission, not role name.

Correct:

```text
requires: di.verification.write
```

Incorrect:

```text
if role == "DOCUMENT_VERIFIER"
```

### RULE-AUTH-004 — Canonical permission namespace

Permissions use the existing form:

```text
<module>.<resource>.<action>
```

Examples:

```text
di.document.upload
di.verification.write
security.member.invite
```

### RULE-AUTH-005 — Namespace ownership

- DI owns `di.*`.
- WPM owns `wpm.*`.
- Security owns `security.*`.

A module cannot register or change another module's namespace.

### RULE-AUTH-006 — Tenant roles are Security-owned

A Tenant role may combine permissions from multiple modules.

Example:

```text
Tenant Role: Process Consultant
  di.document.upload
  di.document.read
  wpm.task.read
  wpm.task.update
```

### RULE-AUTH-007 — Module role templates are templates, not live roles

A module role template is a versioned convenience bundle.

When applied to a Tenant role, Security materializes the selected permissions into that Tenant role and records
template provenance.

A later module-template change MUST NOT silently change the Tenant role.

### RULE-AUTH-008 — No negative permission model in v1.4

Effective permissions are additive.

There is no permission-level `DENY` override in v1.4.

### RULE-AUTH-009 — Platform administration does not imply business-data access

Platform Super Admin and other Platform roles control the Security control plane.

They do not automatically receive `di.*`, `wpm.*`, or future business-module permissions.

A Platform Admin token MUST NOT be accepted as a normal DI/WPM business token.

---

## 4. Authorization object model

```text
Module
  |
  +-- Permissions
  |
  +-- Module Role Templates

Tenant
  |
  +-- Tenant Roles
  |     |
  |     +-- materialized registered permissions
  |     +-- optional template provenance
  |
  +-- Groups
  |     |
  |     +-- USER memberships
  |     +-- Tenant Role assignments
  |
  +-- Direct USER Role assignments
  |
  +-- Explicit USER Location/Schedule assignments

Effective USER Roles
  = Direct ACTIVE Tenant Roles
  + ACTIVE Tenant Roles inherited from ACTIVE Groups

Effective USER Permissions
  = union of ACTIVE permissions on Effective USER Roles
```

Groups and module templates are Security administration concepts. Business modules do not need them in order to
authorize a request.

---

## 5. Reserved standard administrative role catalogue

The following role keys are reserved by Security.

Tenant-created business roles MUST NOT use `platform.*` or the reserved `tenant.*` keys below.

### 5.1 Platform roles

| Role key | Display name | Purpose |
|---|---|---|
| `platform.super_admin` | Platform Super Admin | Highest Security control-plane authority |
| `platform.security_admin` | Platform Security Admin | Security platform configuration and security operations |
| `platform.module_catalog_admin` | Module Catalog Admin | Module/permission/template catalogue administration |
| `platform.auditor` | Platform Auditor | Read-only Platform and cross-Tenant Security audit visibility |

### 5.2 Tenant administrative roles

| Role key | Display name | Purpose |
|---|---|---|
| `tenant.owner` | Tenant Owner | Highest authority inside one Tenant |
| `tenant.admin` | Tenant Admin | Day-to-day Tenant Security administration |
| `tenant.user_admin` | User Admin | Member invitation and lifecycle administration |
| `tenant.rbac_admin` | Role & Group Admin | Roles, Groups and assignment administration |
| `tenant.access_admin` | Access Admin | Locations, schedules and device administration |
| `tenant.security_policy_admin` | Security Policy Admin | Tenant Security/retention policy administration |
| `tenant.security_approver` | Security Approver | Maker-checker approval for privileged access |
| `tenant.auditor` | Tenant Auditor | Read-only Tenant Security audit/review |

### 5.3 Business roles

Business/application roles are Tenant-defined.

Examples such as Process Consultant, Team Lead, Project Manager, Finance User, or Delivery User are not reserved
Security roles and MUST NOT be hard-coded into module authorization logic.

---

## 6. Canonical Security Admin permission catalogue

These permission keys are frozen for v1.4.

### 6.1 Platform permissions

```text
security.platform_admin.read
security.platform_admin.manage
security.security_config.read
security.security_config.manage
security.tenant.create
security.tenant.read
security.tenant.update
security.tenant.suspend
security.tenant.activate
security.tenant.bootstrap_admin
security.module.read
security.module.manage
security.permission.read
security.audit.read
```

`security.tenant.activate` is reserved, but its mutation endpoint remains disabled until the complete Tenant
activation prerequisite catalogue is approved.

### 6.2 Tenant member permissions

```text
security.member.read
security.member.invite
security.member.update
security.member.suspend
security.member.end
security.member.approve
```

### 6.3 Group permissions

```text
security.group.read
security.group.create
security.group.update
security.group.assign
```

### 6.4 Tenant role permissions

```text
security.role.read
security.role.create
security.role.update
security.role.assign
security.permission.read
```

### 6.5 Location/schedule/device permissions

```text
security.location.read
security.location.create
security.location.update
security.location.assign
security.schedule.read
security.schedule.create
security.schedule.update
security.device.read
security.device.approve
security.device.block
security.device.revoke
```

`security.device.block` and `security.device.revoke` are reserved now, but the two mutations remain disabled until
the separate BLOCKED-versus-REVOKED business-semantics decision is frozen.

### 6.6 Policy/approval/audit permissions

```text
security.policy.read
security.policy.update
security.retention.read
security.retention.update
security.privileged_access.approve
security.audit.read
```

---

## 7. Exact standard role permission bundles

### 7.1 `platform.super_admin`

Receives all Platform permissions from section 6.1.

It does not receive business-module permissions automatically.

### 7.2 `platform.security_admin`

```text
security.security_config.read
security.security_config.manage
security.platform_admin.read
security.tenant.read
security.audit.read
```

### 7.3 `platform.module_catalog_admin`

```text
security.module.read
security.module.manage
security.permission.read
security.audit.read
```

### 7.4 `platform.auditor`

```text
security.platform_admin.read
security.security_config.read
security.tenant.read
security.module.read
security.permission.read
security.audit.read
```

No mutation permission is included.

### 7.5 `tenant.owner`

Receives every Tenant-scoped Security administration permission from sections 6.2 through 6.6.

Self-approval of privileged access is still prohibited.

### 7.6 `tenant.admin`

```text
security.member.read
security.member.invite
security.member.update
security.member.suspend
security.member.end
security.group.read
security.group.create
security.group.update
security.group.assign
security.role.read
security.role.create
security.role.update
security.role.assign
security.permission.read
security.location.read
security.location.create
security.location.update
security.location.assign
security.schedule.read
security.schedule.create
security.schedule.update
security.device.read
security.device.approve
security.device.block
security.device.revoke
security.policy.read
security.retention.read
security.audit.read
```

It does not receive:

```text
security.policy.update
security.retention.update
security.privileged_access.approve
```

### 7.7 `tenant.user_admin`

```text
security.member.read
security.member.invite
security.member.update
security.member.suspend
security.member.end
```

### 7.8 `tenant.rbac_admin`

```text
security.member.read
security.group.read
security.group.create
security.group.update
security.group.assign
security.role.read
security.role.create
security.role.update
security.role.assign
security.permission.read
security.audit.read
```

### 7.9 `tenant.access_admin`

```text
security.member.read
security.location.read
security.location.create
security.location.update
security.location.assign
security.schedule.read
security.schedule.create
security.schedule.update
security.device.read
security.device.approve
security.device.block
security.device.revoke
security.audit.read
```

### 7.10 `tenant.security_policy_admin`

```text
security.policy.read
security.policy.update
security.retention.read
security.retention.update
security.audit.read
```

### 7.11 `tenant.security_approver`

```text
security.member.read
security.group.read
security.role.read
security.permission.read
security.privileged_access.approve
security.audit.read
```

### 7.12 `tenant.auditor`

```text
security.member.read
security.group.read
security.role.read
security.permission.read
security.location.read
security.schedule.read
security.device.read
security.policy.read
security.retention.read
security.audit.read
```

---

## 8. Group model

### RULE-GROUP-001 — Tenant-scoped only

Every Group belongs to exactly one Tenant.

### RULE-GROUP-002 — Tenant-defined names

No mandatory Group-name catalogue exists in v1.4.

Tenants may create names such as Sales Team, Delivery Team, Chandigarh Showroom, or any other organization-appropriate
name.

### RULE-GROUP-003 — No nested Groups

A Group cannot contain another Group in v1.4.

### RULE-GROUP-004 — Group receives Roles, not Permissions

Allowed:

```text
Group -> Tenant Role -> Permission
```

Not allowed:

```text
Group -> Permission
```

### RULE-GROUP-005 — No Group-derived location/schedule access

Locations and schedules remain explicit USER assignments.

Group membership cannot grant an approved location.

### RULE-GROUP-006 — Effective RBAC

For an effective Tenant membership:

```text
Effective Roles
  = ACTIVE direct USER Role assignments
  + ACTIVE Role assignments from ACTIVE Group memberships

Effective Permissions
  = union of ACTIVE permissions on all Effective Roles
```

---

## 9. RBAC authorization-version semantics

This section resolves the former Phase 5 `authorization_version` ambiguity for RBAC changes.

### RULE-AUTHVER-001

`tenant_memberships.authorization_version` is the version of a USER's effective Tenant RBAC authorization.

### RULE-AUTHVER-002

It MUST increment transactionally when a change affects that USER's effective permissions:

- direct USER Role assignment added/ended;
- Group membership added/ended;
- Group Role assignment added/ended;
- effective Role changed from ACTIVE to INACTIVE or vice versa;
- Role Permission added/removed for an effective Role;
- effective Permission lifecycle changed so it no longer grants access.

### RULE-AUTHVER-003

If one Role/Group change affects multiple users, every affected Tenant membership receives an increment in the
same logical administration transaction.

### RULE-AUTHVER-004

Location, schedule and device changes remain access-context controls. This document does not redefine them as
RBAC authorization-version events.

---

## 10. Module catalogue and role-template model

### 10.1 Ownership

Security stores the authoritative registered catalogue. Each module owns only its own namespace.

### 10.2 Initial module catalogue API

```text
PUT /security/v1/platform/modules/{moduleKey}/catalog
```

Conceptual request:

```json
{
  "moduleKey": "di",
  "moduleName": "Document Intelligence",
  "catalogVersion": "2.2",
  "permissions": [
    {
      "key": "di.document.upload",
      "name": "Upload Document",
      "description": "Upload a document inside an authorized Tenant context"
    }
  ],
  "roleTemplates": [
    {
      "key": "di.document_operator",
      "name": "Document Operator",
      "description": "Standard DI document-intake template",
      "permissions": [
        "di.subject.create",
        "di.subject.read",
        "di.document.upload",
        "di.document.read"
      ]
    }
  ]
}
```

### 10.3 Catalogue rules

1. `moduleKey` is immutable after registration.
2. every permission key must belong to `{moduleKey}.*`.
3. every template key must belong to `{moduleKey}.*`.
4. a template may reference only the same module's permissions.
5. duplicate permission/template keys are rejected.
6. one module cannot mutate another namespace.
7. update is atomic for one catalogue version.
8. permission lifecycle is `ACTIVE -> DEPRECATED -> RETIRED`.
9. a RETIRED permission cannot be assigned to a new/updated Tenant role.
10. a permission referenced by effective Tenant roles cannot be retired silently.
11. attempted retirement with active references is rejected and returns affected-role information.
12. a template update never mutates existing Tenant roles automatically.
13. applying/upgrading a template is an explicit Tenant/Platform administration action.
14. Security records the template/version provenance used to construct a Tenant role.
15. module catalogue synchronization never grants a permission directly to a user.

### 10.4 Initial caller model

First implementation allows catalogue mutation by:

- Platform Super Admin; or
- Module Catalog Admin.

Automated SYSTEM/SERVICE_INTEGRATION CI synchronization is deferred until the machine-principal phase.

### 10.5 Runtime independence

No business request requires a DI/WPM-to-Security catalogue call.

Runtime remains:

```text
Security JWT
   -> local module JWKS verification
   -> permissions[] check
   -> module business operation
```

---

## 11. DI initial catalogue mapping

At the reviewed DI baseline, `backend/src/verigence/di/auth/permissions.py` contains 28 `di.*` permissions and
eight role bundles.

### 11.1 Permission manifest

The existing 28 `di.*` values are the initial DI permission manifest. Security does not rename them.

### 11.2 Human-facing module role templates

| Current DI bundle | v1.4 module template key |
|---|---|
| `DOCUMENT_OPERATOR` | `di.document_operator` |
| `DOCUMENT_VERIFIER` | `di.document_verifier` |
| `OPERATIONS_VIEWER` | `di.operations_viewer` |
| `UNASSIGNED_INTAKE_OPERATOR` | `di.unassigned_intake_operator` |
| `CONFIGURATION_ADMIN` | `di.configuration_admin` |

### 11.3 Existing DI bundles not imported as Tenant USER role authority

- `TENANT_ADMIN`: not imported as the authoritative Tenant Admin role. Security owns Tenant administration.
- `SERVICE_INTEGRATION`: treated as a future machine permission profile, not a USER Tenant-role template.
- `PLATFORM_ADMIN`: treated as a platform/system profile, not a USER Tenant-role template.

### 11.4 DI runtime rule

DI continues authorizing on `permissions[]`. Role names remain informational only.

---

## 12. Required DI alignment changes

These items are grounded in the reviewed DI `dev` code.

### DI-ALIGN-001 — Exact actor types

DI currently models `SERVICE`; Security models `SERVICE_INTEGRATION`.

DI must use:

```text
USER
SYSTEM
SERVICE_INTEGRATION
```

Unknown actor types MUST fail closed. They MUST NOT default to USER.

### DI-ALIGN-002 — Tenant-scoped SYSTEM

Security's operational SYSTEM model is Tenant-scoped.

DI must not reject a legitimate SYSTEM token merely because it carries `tenant_id`.

Platform Admin authentication is separate and is not a SYSTEM token.

### DI-ALIGN-003 — Tenant path consistency

DI currently contains `{tenantId}` and `{tenant_id}` path styles while its shared Tenant dependency expects
`tenantId`.

Public Tenant routes must be normalized to the approved DI OpenAPI naming and CI must prove:

```text
JWT Tenant A + URL Tenant B -> 403
```

for every Tenant-scoped router.

### DI-ALIGN-004 — Exact endpoint permission coverage

Every DI operation must be checked against DI OpenAPI `x-required-permissions`.

Older read endpoints that currently verify only Tenant identity must also enforce their canonical read permission
when the DI contract specifies one.

### DI-ALIGN-005 — Recovery-document alignment

DI recovery documents containing obsolete Clerk-direct authorization guidance must be updated to the actual
Security JWT/JWKS model.

---

## 13. Platform Super Admin bootstrap and authentication

### RULE-BOOT-001 — Separate from Tenant RBAC

The Platform Super Admin is a Security USER principal with a Platform role assignment. It is not assigned to a
fake/bootstrap Tenant.

### RULE-BOOT-002 — Temporary DEV password remains a secret

The operator has selected a temporary DEV bootstrap password.

The literal value MUST NOT appear in:

- Git;
- this document;
- `.env.example`;
- tests/fixtures;
- logs;
- container images;
- database plaintext.

It is supplied through the deployment secret/environment configuration and stored only as an Argon2id hash.

### RULE-BOOT-003 — Login identifier is explicit input

No default username/email is invented by this design.

Deployment must provide an explicit bootstrap login identifier.

### RULE-BOOT-004 — Startup bootstrap is idempotent

Initial implementation uses deployment-controlled bootstrap logic, not a permanent unauthenticated bootstrap
HTTP endpoint.

The bootstrap service creates the first Platform Super Admin only when:

- bootstrap is permitted in the current environment; and
- no Platform Super Admin assignment exists.

Restarting the service MUST NOT reset an existing password.

### RULE-BOOT-005 — Mandatory first password change

The bootstrap credential is created with:

```text
must_change_password = true
```

Successful initial login may only be used to complete the password change before normal mutation APIs are
available.

### RULE-BOOT-006 — Dedicated Platform Admin JWT

Platform login issues a dedicated control-plane token with audience:

```text
verigence-security-admin
```

It contains Platform roles/permissions and no Tenant business access context.

DI/WPM business APIs MUST reject it.

---

## 14. Tenant creation and first administrator

### RULE-TENANT-001 — Direct Platform creation

Tenant creation is performed directly by Platform Super Admin.

There is no Tenant-creation request/approval workflow in this release.

### RULE-TENANT-002 — New Tenant starts CONFIGURING

```text
POST /security/v1/platform/tenants
```

creates:

```text
status = CONFIGURING
```

### RULE-TENANT-003 — Standard Tenant Admin roles are seeded on creation

The eight reserved Tenant administrative roles from section 5.2 and their bundles from section 7 are created for
the new Tenant in the same Tenant-provisioning transaction.

No business role is created automatically.

### RULE-TENANT-004 — Activation remains fail-closed

Direct Tenant creation does not bypass SEC-032 readiness.

The actual `CONFIGURING -> ACTIVE` mutation remains disabled until the complete activation prerequisite catalogue
is approved.

### RULE-TENANT-005 — First Tenant Owner uses invitation/acceptance

Platform Super Admin creates the first Tenant Owner invitation.

The Owner role becomes effective only after recipient acceptance and the required privileged-access approval
rule. For the first Owner, Platform Super Admin is the authorized approver and cannot be the invitee/subject.

---

## 15. Team-member onboarding and human acceptance

### 15.1 Invitation request model

Conceptual Tenant Admin request:

```json
{
  "displayName": "Employee Name",
  "email": "employee@example.com",
  "mobile": null,
  "employeeCode": "E123",
  "roleIds": ["<tenant-role-uuid>"],
  "groupIds": ["<tenant-group-uuid>"],
  "locationAssignments": [
    {
      "locationId": "<location-uuid>",
      "scheduleId": "<schedule-uuid>"
    }
  ]
}
```

At least one delivery/contact channel is required by the final OpenAPI, but identity is never proven by the
email/mobile string alone.

### 15.2 State before acceptance

Security creates:

```text
USER status          = INVITED
Tenant membership    = PENDING
Invitation status    = PENDING
```

Proposed roles/groups/locations are not effective.

### 15.3 Acceptance endpoint

```text
POST /security/v1/onboarding/invitations/{invitationId}/accept
```

Acceptance requires:

- an authenticated external identity through the Security identity adapter; and
- the one-time invitation acceptance token.

Only a hash of the one-time acceptance token is stored.

### 15.4 Normal non-privileged acceptance

After successful acceptance and revalidation of all referenced Tenant resources:

```text
Invitation        -> ACCEPTED
Tenant membership -> ACTIVE
USER               -> ACTIVE when appropriate
Approved assignments are materialized
```

### RULE-ONBOARD-001 — Human acceptance is mandatory

An administrator cannot silently activate a new person's Tenant membership.

### RULE-ONBOARD-002 — Invitation data is proposed access only

Role, Group and location/schedule selections on the invitation are inert until acceptance/approval is complete.

### RULE-ONBOARD-003 — Email/mobile is not identity proof

Security binds an accepted invitation to the authenticated external identity. It does not infer the Security USER
solely from an email/mobile match.

### RULE-ONBOARD-004 — Provider-neutral state machine

Clerk is the current USER identity provider direction, but the invitation state model is a Security contract and
must not be coupled to a Clerk-only database schema.

---

## 16. Privileged-access maker-checker

### 16.1 Privileged Tenant roles

The following standard role keys require maker-checker:

```text
tenant.owner
tenant.admin
tenant.rbac_admin
tenant.access_admin
tenant.security_policy_admin
tenant.security_approver
```

`tenant.user_admin` and `tenant.auditor` are not automatically in the maker-checker set in v1.4.

### RULE-PRIV-001 — No self-approval

The requester cannot approve their own privileged-access request.

The subject of the role assignment cannot approve their own request.

### RULE-PRIV-002 — Approver permission

Tenant approver must hold:

```text
security.privileged_access.approve
```

within the same Tenant.

### RULE-PRIV-003 — New privileged member

For a new-member invitation containing one or more privileged roles:

1. recipient accepts invitation;
2. a separate privileged-access request exists for each privileged Role assignment;
3. a different authorized approver approves each required request;
4. membership/assignments become effective only when all required approvals succeed.

### RULE-PRIV-004 — Existing member

Adding a privileged Role to an existing member creates a pending privileged-access request. No active Role
assignment is created before approval.

---

## 17. Admin API contract plan

The exact OpenAPI file will be generated from these frozen operations before route implementation.

### 17.1 Platform authentication

| Method | Path | Authentication |
|---|---|---|
| POST | `/security/v1/platform/auth/login` | login name + password |
| POST | `/security/v1/platform/auth/change-password` | Platform bootstrap/admin token |
| GET | `/security/v1/platform/me` | Platform Admin JWT |

Conceptual login request:

```json
{
  "loginName": "<deployment-configured-login>",
  "password": "<secret>"
}
```

### 17.2 Platform Tenant APIs

| Method | Path | Permission |
|---|---|---|
| POST | `/security/v1/platform/tenants` | `security.tenant.create` |
| GET | `/security/v1/platform/tenants` | `security.tenant.read` |
| GET | `/security/v1/platform/tenants/{tenantId}` | `security.tenant.read` |
| PATCH | `/security/v1/platform/tenants/{tenantId}` | `security.tenant.update` |
| POST | `/security/v1/platform/tenants/{tenantId}/owner-invitations` | `security.tenant.bootstrap_admin` |

Conceptual create-Tenant request:

```json
{
  "tenantCode": "ABC-MOTORS",
  "tenantName": "ABC Motors"
}
```

No default Tenant code/name is invented.

### 17.3 Module catalogue APIs

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/platform/modules` | `security.module.read` |
| GET | `/security/v1/platform/modules/{moduleKey}` | `security.module.read` |
| PUT | `/security/v1/platform/modules/{moduleKey}/catalog` | `security.module.manage` |

### 17.4 Member/invitation APIs

| Method | Path | Permission / rule |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/members` | `security.member.read` |
| GET | `/security/v1/admin/tenants/{tenantId}/members/{userId}` | `security.member.read` |
| POST | `/security/v1/admin/tenants/{tenantId}/invitations` | `security.member.invite` |
| GET | `/security/v1/admin/tenants/{tenantId}/invitations` | `security.member.read` |
| POST | `/security/v1/admin/tenants/{tenantId}/invitations/{invitationId}/cancel` | `security.member.update` |
| PATCH | `/security/v1/admin/tenants/{tenantId}/members/{userId}` | `security.member.update` |
| POST | `/security/v1/admin/tenants/{tenantId}/members/{userId}/suspend` | `security.member.suspend` |
| POST | `/security/v1/admin/tenants/{tenantId}/members/{userId}/end` | `security.member.end` |
| POST | `/security/v1/onboarding/invitations/{invitationId}/accept` | authenticated invitee + one-time token |

### 17.5 Group APIs

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/groups` | `security.group.read` |
| POST | `/security/v1/admin/tenants/{tenantId}/groups` | `security.group.create` |
| GET | `/security/v1/admin/tenants/{tenantId}/groups/{groupId}` | `security.group.read` |
| PATCH | `/security/v1/admin/tenants/{tenantId}/groups/{groupId}` | `security.group.update` |
| PUT | `/security/v1/admin/tenants/{tenantId}/groups/{groupId}/members/{userId}` | `security.group.assign` |
| DELETE | `/security/v1/admin/tenants/{tenantId}/groups/{groupId}/members/{userId}` | `security.group.assign` |
| PUT | `/security/v1/admin/tenants/{tenantId}/groups/{groupId}/roles/{roleId}` | `security.group.assign` |
| DELETE | `/security/v1/admin/tenants/{tenantId}/groups/{groupId}/roles/{roleId}` | `security.group.assign` |

Conceptual create-Group request:

```json
{
  "groupKey": "CHANDIGARH-SALES",
  "groupName": "Chandigarh Sales Team",
  "description": null
}
```

Group keys/names are Tenant inputs, not standard global values.

### 17.6 Role APIs

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/roles` | `security.role.read` |
| POST | `/security/v1/admin/tenants/{tenantId}/roles` | `security.role.create` |
| GET | `/security/v1/admin/tenants/{tenantId}/roles/{roleId}` | `security.role.read` |
| PATCH | `/security/v1/admin/tenants/{tenantId}/roles/{roleId}` | `security.role.update` |
| PUT | `/security/v1/admin/tenants/{tenantId}/roles/{roleId}/permissions/{permissionKey}` | `security.role.update` |
| DELETE | `/security/v1/admin/tenants/{tenantId}/roles/{roleId}/permissions/{permissionKey}` | `security.role.update` |
| PUT | `/security/v1/admin/tenants/{tenantId}/members/{userId}/roles/{roleId}` | `security.role.assign` |
| DELETE | `/security/v1/admin/tenants/{tenantId}/members/{userId}/roles/{roleId}` | `security.role.assign` |
| POST | `/security/v1/admin/tenants/{tenantId}/roles/{roleId}/template-upgrades` | `security.role.update` |

Conceptual create-Role request:

```json
{
  "roleKey": "PROCESS_CONSULTANT",
  "roleName": "Process Consultant",
  "description": null,
  "templateKeys": [
    "di.document_operator"
  ],
  "permissionKeys": [
    "wpm.task.read",
    "wpm.task.update"
  ]
}
```

Only registered ACTIVE permissions/templates can be used.

### 17.7 Permission/template discovery

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/permissions` | `security.permission.read` |
| GET | `/security/v1/admin/tenants/{tenantId}/module-role-templates` | `security.permission.read` |

### 17.8 Privileged approval APIs

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/privileged-access-requests` | `security.privileged_access.approve` |
| POST | `/security/v1/admin/tenants/{tenantId}/privileged-access-requests/{requestId}/approve` | `security.privileged_access.approve` |
| POST | `/security/v1/admin/tenants/{tenantId}/privileged-access-requests/{requestId}/reject` | `security.privileged_access.approve` |

### 17.9 Existing Phase 5 administration APIs to expose

v1.4 will expose the existing validated internal services for:

- Tenant Security Policy;
- Security Retention Policy;
- Tenant locations;
- schedules/windows;
- explicit user-location/schedule assignments;
- device list/approval.

The exact paths follow the same `/security/v1/admin/tenants/{tenantId}/...` control-plane convention and the
permissions in section 6.

Device block/revoke mutation routes remain disabled until their business distinction is frozen.

---

## 18. Exact v1.4 logical data contract

Implementation adds a new migration:

```text
migrations/0002_security_admin_control_plane_v1.4.sql
```

The final SQL types/lengths must follow the existing v1.3 conventions. The logical columns and relationships
below are mandatory.

### 18.1 `security.platform_roles`

```text
role_key                PK
role_name
 description            nullable
status                  ACTIVE | INACTIVE
created_at_utc
updated_at_utc
```

The four Platform roles in section 5.1 are seeded by migration.

### 18.2 `security.platform_role_permissions`

```text
role_key                FK -> platform_roles
permission_key          FK -> permissions
assigned_at_utc
PK(role_key, permission_key)
```

### 18.3 `security.platform_user_role_assignments`

```text
assignment_id           PK
user_id                 FK -> users
role_key                FK -> platform_roles
status                  ACTIVE | ENDED
assignment_source       BOOTSTRAP | ADMIN
assigned_by_user_id     nullable FK -> users
assigned_at_utc
ended_at_utc            nullable
```

Only one ACTIVE assignment for the same user/Platform role is allowed.

`assigned_by_user_id` may be null only for the initial BOOTSTRAP assignment.

### 18.4 `security.local_user_credentials`

```text
credential_id           PK
user_id                 FK -> users, unique for v1.4 local-admin auth
login_name              unique
password_hash           Argon2id encoded hash
status                  ACTIVE | REVOKED
must_change_password    boolean
password_changed_at_utc nullable
created_at_utc
updated_at_utc
```

No plaintext password, reset token, or bearer token is stored in this table.

### 18.5 `security.modules`

```text
module_key              PK
module_name
catalog_version
status                  ACTIVE | INACTIVE
created_at_utc
updated_at_utc
updated_by_user_id      FK -> users
```

### 18.6 `security.permissions` v1.4 extension

Existing `permission_key`, `module_key`, `resource_key`, `action_key`, and description remain.

Add/extend:

```text
display_name            nullable for migrated legacy rows, required for new catalogue entries
catalog_version         nullable for migrated legacy rows
status                  ACTIVE | DEPRECATED | RETIRED
updated_at_utc          nullable for migrated legacy rows
```

Existing v1.3 permission keys are not renamed.

### 18.7 `security.module_role_templates`

```text
template_id             PK
module_key              FK -> modules
template_key            unique within module
template_name
description             nullable
catalog_version
status                  ACTIVE | DEPRECATED | RETIRED
created_at_utc
updated_at_utc
```

### 18.8 `security.module_role_template_permissions`

```text
template_id             FK -> module_role_templates
permission_key          FK -> permissions
assigned_at_utc
PK(template_id, permission_key)
```

The permission's `module_key` must match the template module.

### 18.9 `security.role_template_bindings`

This is provenance only; runtime authorization still uses `security.role_permissions`.

```text
binding_id              PK
tenant_id               FK -> tenants
role_id                 FK -> roles
template_id             FK -> module_role_templates
applied_catalog_version
status                  CURRENT | SUPERSEDED
applied_by_user_id      FK -> users
applied_at_utc
superseded_at_utc       nullable
```

### 18.10 `security.groups`

```text
group_id                PK
tenant_id               FK -> tenants
group_key
group_name
description             nullable
status                  ACTIVE | INACTIVE
created_by_user_id      FK -> users
created_at_utc
updated_at_utc
UNIQUE(tenant_id, group_key)
```

### 18.11 `security.group_memberships`

```text
group_membership_id     PK
tenant_id
group_id                FK within same Tenant
user_id                 FK -> users
status                  ACTIVE | ENDED
valid_from_utc          nullable
valid_to_utc            nullable
added_by_user_id        FK -> users
added_at_utc
ended_at_utc            nullable
```

Only one ACTIVE membership for the same Tenant/Group/USER is allowed.

### 18.12 `security.group_role_assignments`

```text
assignment_id           PK
tenant_id
group_id                FK within same Tenant
role_id                 FK within same Tenant
status                  ACTIVE | ENDED
assigned_by_user_id     FK -> users
assigned_at_utc
ended_at_utc            nullable
```

Only one ACTIVE Group/Role assignment is allowed for the same Tenant/Group/Role.

### 18.13 `security.tenant_invitations`

```text
invitation_id                 PK
tenant_id                     FK -> tenants
invited_user_id               FK -> users
invitee_email                 nullable
invitee_mobile                nullable
employee_code                 nullable
acceptance_token_hash         unique, never raw token
proposed_access_json          immutable JSON snapshot
requires_privileged_approval  boolean
status                        PENDING | ACCEPTED | CANCELLED | EXPIRED | REJECTED
invited_by_user_id            FK -> users
invited_at_utc
expires_at_utc
accepted_at_utc               nullable
correlation_id
```

`proposed_access_json` contains only IDs/keys required to materialize the proposed Role, Group and explicit
location/schedule assignments. All references are revalidated before activation.

### 18.14 `security.privileged_access_requests`

One request represents one privileged Role assignment.

```text
request_id               PK
tenant_id                FK -> tenants
subject_user_id          FK -> users
role_id                  FK within same Tenant
source_invitation_id     nullable FK -> tenant_invitations
status                   PENDING | APPROVED | REJECTED | CANCELLED | EXPIRED
requested_by_user_id     FK -> users
requested_at_utc
approved_by_user_id      nullable FK -> users
decided_at_utc           nullable
decision_reason          nullable
correlation_id
```

Requester and subject cannot satisfy their own approval requirement.

### 18.15 `security.admin_change_records`

This structured table avoids inventing uncontrolled free-text `security_events.event_type` values.

```text
admin_change_id          PK
correlation_id
scope_type               PLATFORM | TENANT
tenant_id                nullable FK -> tenants
actor_user_id            FK -> users
operation_key
resource_type
resource_id              nullable
outcome                   SUCCESS | DENIED | FAILED
before_state_json         nullable
after_state_json          nullable
occurred_at_utc
```

Audit state snapshots MUST redact/exclude:

- passwords;
- password hashes;
- invitation raw tokens;
- JWTs;
- client secrets;
- other credentials/secrets.

---

## 19. Platform/Tenant token contracts

### 19.1 Tenant business/Admin USER token

The existing Tenant USER Security JWT remains the token for business modules and Tenant Admin APIs.

Relevant claims include:

```text
sub
tenant_id
actor_type
roles[]
permissions[]
device_id
access_session_id
location_id
authorization_version
```

`permissions[]` is authoritative.

Group IDs and module-template IDs are not required by modules in JWT claims.

### 19.2 Platform Admin token

Platform Admin token:

```text
issuer   = verigence-security
audience = verigence-security-admin
```

It contains Platform roles/permissions and no Tenant business access context.

### 19.3 Cross-module acceptance

DI/WPM business APIs accept only the normal business-token audience they are designed to validate.

A Platform Admin token cannot substitute for a Tenant business token.

---

## 20. Tenant isolation and relationship rules

1. every Tenant Admin route includes `{tenantId}`;
2. Tenant USER token `tenant_id` must equal route `{tenantId}`;
3. Platform tokens are not accepted on Tenant USER Admin routes;
4. Group, Role, USER, location, schedule, device, invitation and approval relationships are validated inside one
   Tenant;
5. knowing a UUID from another Tenant never authorizes its use;
6. module catalogue is Platform-scoped, not Tenant-scoped;
7. CI must contain cross-Tenant negative tests for every Tenant Admin resource family.

---

## 21. Administration audit rules

### RULE-AUDIT-001

Every successful Admin mutation creates one structured `admin_change_records` entry in the same logical
transaction where possible.

### RULE-AUDIT-002

Denied and failed administrative operations remain traceable by correlation ID.

### RULE-AUDIT-003

Audit records never contain credential material.

### RULE-AUDIT-004

Module catalogue changes record the module/catalog version and operation in structured before/after state.

### RULE-AUDIT-005

Privileged-access request and decision records remain queryable independently from general Admin change records.

---

## 22. No-silent-change rules

The following are prohibited:

- module template changes silently changing Tenant Roles;
- module catalogue synchronization directly granting USER permissions;
- Tenant Admin creating arbitrary unregistered permission keys;
- direct Group-to-Permission assignment;
- nested Groups;
- Group-derived location/schedule access;
- privileged Role activation without maker-checker;
- self-approval of privileged access;
- invited member activation without human acceptance;
- plaintext password storage;
- committing the temporary bootstrap password;
- Platform Admin token being used for DI/WPM business access;
- module authorization based on Role names;
- unknown actor type becoming USER;
- changing immutable migration `0001_security_baseline_v1.3.sql`;
- enabling Tenant activation before SEC-032 prerequisites are complete;
- implementing device BLOCKED/REVOKED mutation semantics by assumption.

---

## 23. Implementation sequence

The Admin Control Plane remains the primary workstream before Phase 6 machine actors.

### Increment A — v1.4 schema + standard catalogues

Implement:

- `0002_security_admin_control_plane_v1.4.sql`;
- `security.*` permissions from section 6;
- standard Platform Role seeds/bundles;
- standard Tenant Admin Role definitions/seeding service;
- module/template persistence;
- Groups persistence;
- invitation persistence;
- privileged request persistence;
- structured Admin audit persistence.

Definition of done:

- v1.3 migration checksum unchanged;
- migration succeeds on real Neon;
- constraints/uniqueness/cross-Tenant FK behavior tested;
- standard permission/Role bundles match sections 6/7 exactly.

### Increment B — Platform Super Admin bootstrap + direct Tenant creation

Implement:

- deployment-secret bootstrap;
- Argon2id credential hashing;
- mandatory first password change;
- Platform Admin JWT;
- Platform login/me/change-password APIs;
- Tenant create/list/get/update APIs;
- standard Tenant Admin Role seed transaction;
- first Owner invitation API.

Definition of done:

- literal bootstrap credential absent from Git/DB/logs;
- bootstrap cannot overwrite an existing administrator;
- wrong password fails closed;
- Platform token rejected by DI business API;
- new Tenant is `CONFIGURING`.

### Increment C — Module catalogue API + DI synchronization

Implement:

- Platform module APIs;
- DI 28-permission manifest synchronization;
- five DI USER role templates;
- namespace/version validation;
- permission lifecycle;
- template provenance;
- reference/impact checks.

Definition of done:

- DI cannot register outside `di.*`;
- template update does not mutate an existing Tenant Role;
- permission retirement with active Role references is blocked/reported;
- explicit template upgrade changes Role permissions and affected USER authorization versions.

### Increment D — Groups + effective RBAC

Implement:

- Group CRUD;
- Group membership;
- Group Role assignment;
- direct + Group Role resolution;
- authorization-version bumping.

Definition of done:

- no nested Group;
- no direct Group permission;
- no Group-derived location;
- cross-Tenant relationships rejected;
- effective permissions match the direct+Group Role union.

### Increment E — Tenant Role Admin APIs

Implement:

- Role CRUD;
- registered Permission add/remove;
- template application/upgrade;
- direct USER Role assignment;
- reserved standard Role protection;
- authorization-version bumping;
- maker-checker routing for privileged standard Roles.

### Increment F — Team-member invitation + acceptance

Implement:

- invitation create/list/cancel;
- one-time acceptance token hashing;
- authenticated recipient acceptance;
- external identity binding;
- PENDING -> ACTIVE membership;
- materialization of approved assignments.

### Increment G — Privileged maker-checker

Implement:

- privileged request creation;
- approve/reject;
- no requester/subject self-approval;
- Role activation only after approval;
- Admin audit.

### Increment H — Existing policy/access Admin services

Expose existing validated services for:

- Security Policy;
- Retention Policy;
- locations;
- schedules/windows;
- explicit USER location/schedule assignment;
- device read/approval.

Block/revoke mutations remain deferred until semantics are frozen.

### Increment I — DI alignment

In `verigence/verigence-di`:

- `SERVICE` -> `SERVICE_INTEGRATION`;
- unknown actor fails closed;
- Tenant-scoped SYSTEM token handling aligned;
- Tenant path parameter handling normalized;
- all 54 operations audited against DI permission contract;
- cross-Tenant negative tests added;
- stale Clerk-direct recovery docs corrected.

### Increment J — deployed Security -> DI E2E

Prove:

```text
Platform Super Admin login
  -> direct Tenant creation
  -> DI catalogue synchronization
  -> first Tenant Owner invitation
  -> Owner human acceptance + approval
  -> Tenant Group/Role configuration
  -> USER effective Security JWT permissions
  -> DI verifies Security JWKS/JWT
  -> allowed DI operation succeeds with required di.* permission
  -> same operation fails without permission
  -> cross-Tenant URL fails
```

Railway/Neon deployed E2E is mandatory before the Admin Control Plane phase is marked complete.

---

## 24. Required test matrix

At minimum, automated tests must prove:

1. v1.3 baseline migration is unchanged.
2. v1.4 migration applies to real Neon.
3. standard permission keys and Role bundles are exact.
4. Platform bootstrap occurs only when enabled and no Super Admin exists.
5. bootstrap restart does not reset credentials.
6. password is Argon2id-hashed and plaintext never persisted/logged.
7. first password change is required.
8. Platform token cannot authorize DI/WPM business API.
9. non-authorized Platform user cannot create Tenant.
10. direct Tenant creation results in `CONFIGURING`.
11. standard Tenant Admin Roles are seeded once.
12. module namespace ownership is enforced.
13. DI initial manifest registers exactly the reviewed DI permissions.
14. module template update does not silently mutate Tenant Roles.
15. Tenant Admin cannot create an unregistered Permission.
16. Group cannot contain Group.
17. Group cannot directly receive Permission.
18. Group cannot grant location/schedule.
19. direct + Group Roles calculate correct effective permissions.
20. RBAC-effective changes bump every affected authorization version.
21. invitation cannot activate membership before acceptance.
22. raw invitation acceptance token is never stored.
23. expired/cancelled invitation cannot activate.
24. external identity cannot be rebound incorrectly.
25. privileged Role cannot activate before approval.
26. requester/subject cannot self-approve.
27. cross-Tenant identifiers are rejected for all Admin resources.
28. every successful Admin mutation creates structured audit evidence.
29. Admin audit state never contains credentials.
30. DI unknown actor type fails closed.
31. DI accepts canonical `SERVICE_INTEGRATION` where applicable.
32. DI Tenant path mismatch returns 403 for every Tenant router.
33. every DI operation enforces its declared permission contract.
34. DI authorizes from Security JWT permissions without per-request Security API/DB lookup.
35. deployed Security -> DI E2E passes on immutable validated artifacts.

---

## 25. Explicitly deferred / still blocked

This document does not invent:

- device `BLOCKED` versus `REVOKED` mutation semantics;
- the complete SEC-032 Tenant activation prerequisite catalogue;
- persistent cross-replica idempotency storage;
- live Clerk invitation/provider API orchestration details;
- automated module synchronization by machine principal;
- WPM catalogue contents before WPM is separately reviewed;
- nested Groups;
- negative/deny permissions;
- Group-derived location/schedule access;
- automatic mutation of Tenant Roles when a module template changes;
- a production bootstrap password/value;
- old v1.3 lifecycle route shapes still gated by the unavailable v1.3 OpenAPI.

---

## 26. Context-reset recovery

After reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
3. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`;
4. `docs/IMPLEMENTATION_STATUS.md`;
5. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`;
6. current Security `dev` and open Security PRs;
7. for DI integration, current DI `dev` and:
   - `DI_MASTER_REFERENCE.md`;
   - `backend/src/verigence/di/auth/permissions.py`;
   - `backend/src/verigence/di/auth/verifier.py`;
   - `backend/src/verigence/di/auth/dependencies.py`.

Do not reconstruct the Admin Control Plane from chat history after this design is merged.

---

## 27. Final model

```text
                         VERIGENCE SECURITY
                                |
            +-------------------+-------------------+
            |                                       |
     PLATFORM CONTROL PLANE                  TENANT CONTROL PLANE
            |                                       |
 Platform Super Admin                         Tenant Owner/Admins
 Platform Security Admin                            |
 Module Catalog Admin                               +-- Members/Invitations
 Platform Auditor                                   +-- Groups
            |                                       +-- Tenant Roles
            |                                       +-- Locations/Schedules
       Module Catalogue                             +-- Devices/Policies
            |                                             |
     +------+------+                                      |
     |             |                                      v
    DI            WPM                             Effective Tenant Roles
Permissions    Permissions                                |
Templates      Templates                                  v
     |             |                              Effective Permissions
     +------+------+                                      |
            |                                             v
            +------------------------------------- Security USER JWT
                                                          |
                                      +-------------------+-------------------+
                                      |                                       |
                                      v                                       v
                                     DI                                      WPM
                              checks di.* permission                  checks wpm.* permission
```

The governing rule is:

> Modules define capabilities and optional module role templates. Security owns authoritative Platform/Tenant
> administrators, Tenant Roles, Groups, assignments, effective permissions, onboarding, approvals and tokens.
> Modules authorize locally from the Security JWT `permissions[]` claim.
