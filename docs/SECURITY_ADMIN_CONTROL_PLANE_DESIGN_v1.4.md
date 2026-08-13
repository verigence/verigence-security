# Verigence Security Admin Control Plane and Cross-Module Authorization Design v1.4

**Status:** APPROVED DIRECTION FOR IMPLEMENTATION  
**Date:** 2026-08-13  
**Repository:** `verigence/verigence-security`  
**Security baseline reviewed:** `dev@ca3e0cd08ebb12040eefa911dfc147e3643e09ac`  
**DI baseline reviewed:** `verigence/verigence-di dev@caf0dfab8d80357ab76568538b8f73f2d2e05fc0`  
**Supersedes:** no Security v1.3 normative artifact. This is a versioned v1.4 control-plane extension.

---

## 1. Purpose

This document is the implementation authority for the Verigence Security administration control plane,
standard administrative roles, Tenant groups, cross-module permission registration, module role templates,
Tenant/team-member onboarding, privileged-access approval, and Security-to-module authorization behavior.

It exists to remove the ambiguity that blocked public Security Admin APIs in Phase 5.

This document does **not** silently reinterpret Security v1.3. It separates:

1. existing Security v1.3 facts;
2. behavior already implemented and validated in Security;
3. behavior already implemented in Document Intelligence (DI);
4. new v1.4 decisions explicitly adopted for the control plane.

If a future requirement conflicts with this document, the design must be versioned again before code changes.

---

## 2. Grounded source facts

### 2.1 Existing Security v1.3 facts retained unchanged

The current approved Security schema already establishes these facts:

- Security is multi-Tenant.
- Tenant lifecycle includes `CONFIGURING`, `ACTIVE`, `SUSPENDED`, `OFFBOARDING`, and `OFFBOARDED`.
- Security Principal actor types are exactly:
  - `USER`;
  - `SYSTEM`;
  - `SERVICE_INTEGRATION`.
- USER status includes `INVITED` and `ACTIVE`.
- Tenant membership status includes `PENDING` and `ACTIVE`.
- permissions are globally registered with `module_key`, `resource_key`, and `action_key`.
- roles are Tenant-scoped.
- roles receive permissions through `security.role_permissions`.
- users receive roles through `security.user_role_assignments`.
- machine principals receive Tenant scope and permissions through the existing principal scope/grant model.
- USER access tokens contain effective permissions and Tenant context.
- Security remains the source of truth for identity, Tenant membership, access policy, RBAC, devices,
  sessions, and Security JWT issuance.

The immutable baseline migration remains `migrations/0001_security_baseline_v1.3.sql` and MUST NOT be
rewritten to implement v1.4.

### 2.2 Existing Phase 5 implementation retained

Phase 5 has already implemented and Neon-validated internal administration services for:

- Tenant Security Policy;
- Security Retention Policy;
- Tenant locations;
- access schedules and schedule windows;
- USER Security-side onboarding persistence;
- Tenant memberships;
- employee-location assignments;
- canonical permissions;
- Tenant roles;
- role-permission grants;
- direct user-role assignments;
- fail-closed Tenant activation-readiness foundation.

The v1.4 Admin APIs will expose and extend these existing services rather than creating a parallel
administration model.

### 2.3 Existing DI implementation facts retained

The current DI implementation already follows the target runtime model in the important areas:

- DI verifies Security-issued JWTs using the Security JWKS endpoint.
- DI expects Security issuer `verigence-security`.
- DI treats `permissions[]` as authoritative for authorization.
- DI treats `roles[]` as informational/backward-compatible data.
- DI has `require_permission()` and `require_tenant_permission()` dependencies.
- DI already has a canonical `di.*` permission catalogue.
- DI currently defines 28 `di.*` permissions.
- DI currently has eight role bundles used mainly for defaults/mock behavior.

The DI permission catalogue is therefore the first real module catalogue that will be synchronized into
Security v1.4.

---

## 3. Core authorization principles

The following rules are normative for v1.4.

### RULE-AUTH-001 — Security is the authorization authority

Security owns:

- users and machine principals;
- Tenant memberships;
- platform administrators;
- registered module catalogue;
- canonical permissions;
- Tenant roles;
- groups;
- user/group role assignments;
- effective permission calculation;
- Security access tokens.

Application modules MUST NOT maintain a second authoritative user-role assignment store.

### RULE-AUTH-002 — Modules own capability definitions, not user authorization

A module such as DI or WPM owns:

- the operations it exposes;
- its canonical permission definitions;
- optional standard role templates that bundle its own permissions.

A module does **not** own the runtime Tenant roles assigned to users.

### RULE-AUTH-003 — Permissions are the runtime contract

Application modules MUST authorize on canonical permissions.

Correct:

```text
requires: di.verification.write
```

Incorrect:

```text
if role == "DOCUMENT_VERIFIER"
```

Role names are never a stable contract between Security and a business module.

### RULE-AUTH-004 — Canonical permission namespace

Permissions retain the existing module-prefixed form:

```text
<module>.<resource>.<action>
```

Examples already in use:

```text
di.document.upload
di.verification.write
di.tenant_config.read
```

Security administration permissions use the `security.*` namespace.

### RULE-AUTH-005 — Namespace ownership

A registered module may only publish permissions and role templates within its own namespace.

Examples:

- DI owns `di.*`.
- WPM owns `wpm.*`.
- Security owns `security.*`.

DI MUST NOT publish `wpm.*` or `security.*` entries.

### RULE-AUTH-006 — Tenant roles are Security-owned

A Tenant role may combine permissions originating from multiple modules.

Example:

```text
Tenant Role: Process Consultant
  di.document.upload
  di.document.read
  wpm.task.read
  wpm.task.update
```

The role is stored and assigned by Security, not DI or WPM.

### RULE-AUTH-007 — Module role templates are templates only

A module role template is a versioned convenience bundle of permissions published by a module.

Applying a template to a Tenant role materializes the selected permissions into the Tenant role.

A later change to the module template MUST NOT silently change existing Tenant roles.

Template upgrades require an explicit Security Admin action after impact review.

### RULE-AUTH-008 — No negative permissions in v1.4

v1.4 uses additive permissions only.

Effective permissions are the union of permissions from effective roles.

There is no `DENY` permission override model in v1.4.

### RULE-AUTH-009 — Platform administration does not grant business-data access

Platform Super Admin and other platform administrative roles control the Security control plane.

They do not automatically receive `di.*`, `wpm.*`, or future module business permissions.

A Platform Super Admin token MUST NOT be accepted as a normal DI/WPM Tenant business token.

---

## 4. Authorization object model

```text
Module
  |
  +-- Permission definitions
  |
  +-- Module role templates

Security Tenant
  |
  +-- Tenant roles
  |     |
  |     +-- materialized permissions
  |     +-- optional template provenance
  |
  +-- Groups
  |     |
  |     +-- Users
  |     +-- Tenant roles
  |
  +-- Direct user-role assignments
  |
  +-- Explicit user-location/schedule assignments

Effective USER roles
  = direct Tenant roles
  + roles inherited through active groups

Effective USER permissions
  = union of ACTIVE permissions on all effective ACTIVE roles
```

Groups and module templates are administration abstractions. Modules consume effective permissions from the
Security JWT and do not need to understand groups or templates.

---

## 5. Standard administrative role catalogue

Standard administrative role keys are reserved by Security.

Tenant administrators may create additional business roles but MUST NOT create another role using a reserved
standard administrative role key.

### 5.1 Platform roles

| Role key | Display name | Scope | Purpose |
|---|---|---|---|
| `platform.super_admin` | Platform Super Admin | Platform | Highest Security control-plane authority |
| `platform.security_admin` | Platform Security Admin | Platform | Security platform configuration and security operations |
| `platform.module_catalog_admin` | Module Catalog Admin | Platform | Module, permission and role-template catalogue administration |
| `platform.auditor` | Platform Auditor | Platform | Read-only control-plane and cross-Tenant Security audit visibility |

### 5.2 Tenant administrative roles

| Role key | Display name | Scope | Purpose |
|---|---|---|---|
| `tenant.owner` | Tenant Owner | One Tenant | Highest authority inside one Tenant |
| `tenant.admin` | Tenant Admin | One Tenant | Day-to-day Tenant administration |
| `tenant.user_admin` | User Admin | One Tenant | Member invitation and lifecycle administration |
| `tenant.rbac_admin` | Role & Group Admin | One Tenant | Roles, groups, permissions and assignments |
| `tenant.access_admin` | Access Admin | One Tenant | Locations, schedules and devices |
| `tenant.security_policy_admin` | Security Policy Admin | One Tenant | Security/retention policy administration |
| `tenant.security_approver` | Security Approver | One Tenant | Maker-checker approval for privileged access |
| `tenant.auditor` | Tenant Auditor | One Tenant | Read-only Tenant Security audit/review |

### 5.3 Business roles

Business/application roles are Tenant-defined and are not part of the reserved Security administrative role
catalogue.

Examples such as Process Consultant, Team Lead, Project Manager, Finance User, Delivery User, or business
Auditor are created by a Tenant from registered module permissions/templates.

Security MUST NOT hard-code these business role names into application authorization logic.

---

## 6. Security administration permission catalogue

The following `security.*` permission keys are the v1.4 control-plane contract.

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

`security.tenant.activate` is reserved by the catalogue but its mutation endpoint MUST remain disabled until the
complete Tenant activation prerequisite contract is approved.

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

### 6.5 Access-control administration permissions

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

The business distinction between device `BLOCKED` and `REVOKED` remains separately open and MUST be frozen
before the two mutation endpoints are implemented.

### 6.6 Policy and approval permissions

```text
security.policy.read
security.policy.update
security.retention.read
security.retention.update
security.privileged_access.approve
security.audit.read
```

---

## 7. Standard role permission bundles

### 7.1 Platform Super Admin

`platform.super_admin` receives every Platform `security.*` permission required to:

- manage platform administrators;
- create/read/update/suspend Tenants;
- bootstrap the first Tenant Owner/Admin invitation;
- manage the module catalogue;
- read Security audit information;
- manage Security platform configuration.

It does not automatically receive module business permissions.

### 7.2 Platform Security Admin

`platform.security_admin` receives:

```text
security.security_config.read
security.security_config.manage
security.tenant.read
security.platform_admin.read
security.audit.read
```

It does not create Tenants or manage module catalogues unless separately granted.

### 7.3 Module Catalog Admin

`platform.module_catalog_admin` receives:

```text
security.module.read
security.module.manage
security.permission.read
security.audit.read
```

### 7.4 Platform Auditor

`platform.auditor` receives read-only Platform Security permissions only.

No mutation permission is included.

### 7.5 Tenant Owner

`tenant.owner` receives the full Tenant Security administration set, including policy administration and
privileged-access approval.

Self-approval is prohibited even for the Tenant Owner.

### 7.6 Tenant Admin

`tenant.admin` receives day-to-day administration permissions for:

- members;
- groups;
- roles;
- locations;
- schedules;
- devices;
- read-only policy visibility.

It does not automatically receive `security.policy.update`, `security.retention.update`, or
`security.privileged_access.approve`.

### 7.7 User Admin

`tenant.user_admin` receives member read/invite/update/suspend/end permissions.

### 7.8 Role & Group Admin

`tenant.rbac_admin` receives group, role, permission-read, and role/group assignment permissions.

### 7.9 Access Admin

`tenant.access_admin` receives location, schedule, and device administration permissions.

### 7.10 Security Policy Admin

`tenant.security_policy_admin` receives Security policy and retention read/update permissions.

### 7.11 Security Approver

`tenant.security_approver` receives:

```text
security.member.read
security.role.read
security.group.read
security.privileged_access.approve
security.audit.read
```

### 7.12 Tenant Auditor

`tenant.auditor` receives read-only Tenant Security permissions for members, groups, roles, permissions,
locations, schedules, devices, policies, and audit evidence.

---

## 8. Group model

### RULE-GROUP-001 — Groups are Tenant-scoped

Every group belongs to exactly one Tenant.

### RULE-GROUP-002 — Group names are Tenant-defined

v1.4 does not mandate group names such as Sales, Finance, or Delivery.

Examples are allowed, but there is no global standard group-name catalogue.

### RULE-GROUP-003 — No nested groups in v1.4

A group cannot contain another group.

This prevents recursive authorization resolution and circular memberships.

### RULE-GROUP-004 — Groups receive roles, never permissions directly

Correct:

```text
Group -> Tenant Role -> Permissions
```

Not allowed:

```text
Group -> Permission
```

### RULE-GROUP-005 — Location access remains explicit per USER

Groups do not grant locations or schedules in v1.4.

The existing Security rule that a USER must be explicitly assigned to an approved Tenant location/schedule
continues unchanged.

### RULE-GROUP-006 — Effective authorization

For an ACTIVE Tenant membership:

```text
Effective Roles
  = ACTIVE direct user-role assignments
  + ACTIVE roles assigned through ACTIVE group memberships

Effective Permissions
  = ACTIVE permissions on all Effective Roles
```

---

## 9. Authorization version semantics

This document resolves the Phase 5 `authorization_version` ambiguity for RBAC changes.

### RULE-AUTHVER-001

`tenant_memberships.authorization_version` represents the version of the USER's effective Tenant RBAC
authorization.

### RULE-AUTHVER-002

The value MUST increment transactionally when an administrative change affects a USER's effective permissions,
including:

- direct user-role assignment added/ended;
- group membership added/ended;
- group-role assignment added/ended;
- role status change affecting the USER;
- role-permission grant added/ended for an effective role;
- permission lifecycle change that removes an effective permission.

### RULE-AUTHVER-003

If a role/group change affects multiple users, every affected ACTIVE/PENDING Tenant membership must receive the
increment in the same logical administration transaction.

### RULE-AUTHVER-004

Location, schedule, and device changes remain access-context controls and are not redefined as RBAC
`authorization_version` events by this document.

Their existing lifecycle enforcement remains separate.

---

## 10. Module catalogue model

Security maintains the authoritative copy of every registered module's permissions and optional role templates.

### 10.1 Module catalogue API

Initial v1.4 operation:

```text
PUT /security/v1/platform/modules/{moduleKey}/catalog
```

The update is atomic for one module catalogue version.

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
      "description": "Upload one document within an authorized Tenant context"
    }
  ],
  "roleTemplates": [
    {
      "key": "di.document_operator",
      "name": "Document Operator",
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

The exact OpenAPI schema will be generated from this design before route implementation.

### 10.2 Catalogue update rules

1. `moduleKey` is immutable once registered.
2. every published permission must belong to the same module namespace.
3. every role template must contain only permissions owned by the same module.
4. catalogue update is atomic.
5. duplicate permission keys are rejected.
6. a module cannot overwrite Security or another module's catalogue.
7. removal from a new manifest does not silently delete a permission used by Tenant roles.
8. permissions follow lifecycle `ACTIVE -> DEPRECATED -> RETIRED`.
9. `RETIRED` cannot become effective in new role configuration.
10. existing Tenant roles do not automatically change when a template changes.
11. template changes produce impact information for administrators.
12. template upgrade of a Tenant role is an explicit administration action.

### 10.3 Initial caller model

The first implementation allows catalogue mutation by Platform Super Admin or Module Catalog Admin.

Future SYSTEM/SERVICE_INTEGRATION-based CI synchronization may be added after the machine-principal phase. It is
not required for the first Admin Control Plane release.

### 10.4 Runtime independence

DI/WPM do not call the module catalogue API for each business request.

Catalogue synchronization is a deployment/administration concern.

Runtime authorization remains local JWT verification:

```text
Security JWT -> module JWKS verification -> permissions[] check -> business operation
```

---

## 11. DI catalogue mapping

At the reviewed DI baseline, `backend/src/verigence/di/auth/permissions.py` defines 28 canonical permissions and
eight role bundles.

### 11.1 DI permissions

The existing 28 `di.*` values are the initial DI permission manifest. They are not renamed by Security v1.4.

### 11.2 DI human role templates to publish

The following existing DI bundles become module role templates:

| Current DI bundle | Security module template key |
|---|---|
| `DOCUMENT_OPERATOR` | `di.document_operator` |
| `DOCUMENT_VERIFIER` | `di.document_verifier` |
| `OPERATIONS_VIEWER` | `di.operations_viewer` |
| `UNASSIGNED_INTAKE_OPERATOR` | `di.unassigned_intake_operator` |
| `CONFIGURATION_ADMIN` | `di.configuration_admin` |

### 11.3 DI bundles that do not become Tenant business-role authority

- DI `TENANT_ADMIN` is not imported as the authoritative Tenant Admin role. Tenant administration belongs to
  Security standard roles.
- DI `SERVICE_INTEGRATION` is treated as a machine permission profile, not a USER Tenant role template.
- DI `PLATFORM_ADMIN` is treated as a platform/system permission profile, not a USER Tenant role template.

### 11.4 DI runtime rule

DI continues checking `permissions[]` and MUST NOT require a DI role name for authorization.

---

## 12. Required DI alignment changes

These are implementation tasks discovered from the actual DI `dev` code and are part of the cross-module
integration plan.

### DI-ALIGN-001 — Actor type alignment

DI currently models `SERVICE`; Security models `SERVICE_INTEGRATION`.

DI must use the exact Security actor-type values:

```text
USER
SYSTEM
SERVICE_INTEGRATION
```

An unknown Security actor type MUST fail closed. It MUST NOT default to `USER`.

### DI-ALIGN-002 — SYSTEM Tenant scope

Security's Tenant operational SYSTEM model is Tenant-scoped.

DI must not reject a legitimate Tenant-scoped SYSTEM token merely because `tenant_id` exists.

Platform Super Admin authentication is a separate control-plane token and is not a SYSTEM actor token.

### DI-ALIGN-003 — Tenant path consistency

DI currently contains both `{tenantId}` and `{tenant_id}` route parameter styles while the shared Tenant
dependency expects `tenantId`.

All public DI Tenant routes must be normalized to the approved OpenAPI path parameter naming, and CI must prove:

```text
JWT Tenant A + URL Tenant B -> 403
```

for every Tenant-scoped router.

### DI-ALIGN-004 — Endpoint permission completeness

Some older DI read routes currently verify Tenant identity without enforcing their specific read permission.

Every DI operation must be audited against the DI OpenAPI `x-required-permissions` contract.

Examples that require correction include basic Subject/Document reads where a canonical read permission already
exists.

### DI-ALIGN-005 — Documentation alignment

DI recovery documentation must be updated to remove obsolete Clerk-direct authorization guidance where current
code already expects Security-issued JWT + Security JWKS.

---

## 13. Platform Super Admin bootstrap

A Platform Super Admin is required before any Tenant exists.

Tenant RBAC cannot bootstrap Tenant creation because there is no Tenant membership yet.

### RULE-BOOT-001 — Platform Super Admin is outside Tenant RBAC

The Platform Super Admin is a Security USER principal with a Platform role assignment, not a role inside an
arbitrary Tenant.

### RULE-BOOT-002 — No bootstrap credential in source control

The operator has selected a temporary DEV bootstrap password.

The literal credential MUST NOT be committed to Git, documentation, test fixtures, logs, or container images.

It must be supplied through environment/secret configuration and stored only as an Argon2id password hash.

### RULE-BOOT-003 — No hard-coded login identifier

No default username/email is invented by this design.

The bootstrap login identifier is supplied explicitly through deployment configuration.

### RULE-BOOT-004 — Bootstrap is DEV-controlled and idempotent

Initial implementation uses a startup/bootstrap service controlled by environment configuration.

It creates the first Platform Super Admin only when:

- the environment permits bootstrap; and
- no Platform Super Admin exists.

It MUST NOT reset an existing administrator's password on subsequent starts.

### RULE-BOOT-005 — First-login password change

The bootstrap credential is temporary.

The created local credential is marked `must_change_password=true`.

Before normal control-plane mutations are allowed, the bootstrap administrator must set a replacement password.

### RULE-BOOT-006 — Platform admin token

Platform admin login issues a dedicated Security control-plane JWT with a separate audience from ordinary Tenant
business tokens.

Target audience:

```text
verigence-security-admin
```

The token contains Platform role/permission claims and no Tenant business context.

DI/WPM MUST reject this token as a normal business token.

---

## 14. Tenant creation and activation

### RULE-TENANT-001 — Tenant creation is direct Platform administration

For the current release, Tenant creation is performed directly by Platform Super Admin.

There is no Tenant-creation request/approval workflow.

### RULE-TENANT-002 — New Tenant starts CONFIGURING

```text
POST /security/v1/platform/tenants
```

creates the Tenant in `CONFIGURING` state.

### RULE-TENANT-003 — Tenant activation is not bypassed

Direct Tenant creation does not imply automatic activation.

`security.tenant.activate` is reserved, but actual activation remains fail-closed until the complete approved
activation prerequisite catalogue is frozen.

This design does not introduce a hidden `CONFIGURING -> ACTIVE` bypass.

### RULE-TENANT-004 — First Tenant Owner is invited

After Tenant creation, Platform Super Admin can initiate the first Tenant Owner invitation.

The person must explicitly accept membership before the Tenant Owner role becomes effective.

---

## 15. Team-member onboarding and human acceptance

Human acceptance remains mandatory for Tenant team-member onboarding.

### 15.1 Normal onboarding flow

```text
Authorized Tenant Admin
        |
        | creates invitation
        v
USER status = INVITED
Tenant membership = PENDING
Invitation = PENDING
        |
        | recipient authenticates and explicitly accepts
        v
Security binds/validates external identity
        |
        v
Membership -> ACTIVE
User -> ACTIVE (when appropriate)
Approved roles/groups/locations become effective
```

### RULE-ONBOARD-001

An administrator cannot silently activate a new person's Tenant membership without recipient acceptance.

### RULE-ONBOARD-002

An invitation may contain proposed:

- Tenant role assignments;
- group memberships;
- explicit location/schedule assignments.

They do not become effective until the invitation reaches the required acceptance/approval state.

### RULE-ONBOARD-003

Email/mobile is invitation/contact data, not sufficient proof of user identity.

Security binds an accepted invitation to the authenticated external identity; it does not infer identity only from
an email string.

### RULE-ONBOARD-004

Live Clerk invitation/provider orchestration remains a separate provider-integration task.

The Admin API contract and Security-side state machine are not dependent on Clerk being the only future provider.

---

## 16. Privileged-access maker-checker

Privileged Security administrative assignments require separation of duties.

### 16.1 Privileged standard Tenant roles

The following standard role assignments are privileged in v1.4:

```text
tenant.owner
tenant.admin
tenant.rbac_admin
tenant.access_admin
tenant.security_policy_admin
tenant.security_approver
```

`tenant.user_admin` and `tenant.auditor` remain administrative roles but are not automatically placed in the
maker-checker set by this rule.

### RULE-PRIV-001 — Requester cannot approve own request

The user who creates a privileged-access request cannot be its approver.

### RULE-PRIV-002 — Approver permission

Approver must hold:

```text
security.privileged_access.approve
```

within the same Tenant.

### RULE-PRIV-003 — New-member privileged onboarding

If an invitation includes a privileged role, the membership/privileged assignments become effective only after:

1. recipient acceptance; and
2. approval by a different authorized Security Approver/Tenant Owner.

### RULE-PRIV-004 — Existing-member privileged assignment

Adding a privileged role to an existing member creates a pending privileged-access request. The role assignment
is materialized only after approval.

---

## 17. Admin API surface

The API is split into Platform and Tenant control planes.

### 17.1 Platform authentication

| Method | Path | Purpose |
|---|---|---|
| POST | `/security/v1/platform/auth/login` | Local Platform Admin login |
| POST | `/security/v1/platform/auth/change-password` | Mandatory/normal password change |
| GET | `/security/v1/platform/me` | Current Platform admin identity/permissions |

Bootstrap account creation is deployment-controlled and is not exposed as a permanent unauthenticated public
endpoint.

### 17.2 Platform Tenant APIs

| Method | Path | Permission |
|---|---|---|
| POST | `/security/v1/platform/tenants` | `security.tenant.create` |
| GET | `/security/v1/platform/tenants` | `security.tenant.read` |
| GET | `/security/v1/platform/tenants/{tenantId}` | `security.tenant.read` |
| PATCH | `/security/v1/platform/tenants/{tenantId}` | `security.tenant.update` |
| POST | `/security/v1/platform/tenants/{tenantId}/owner-invitations` | `security.tenant.bootstrap_admin` |

A future activation endpoint uses `security.tenant.activate` but is not enabled until activation prerequisites are
frozen.

### 17.3 Module catalogue APIs

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/platform/modules` | `security.module.read` |
| GET | `/security/v1/platform/modules/{moduleKey}` | `security.module.read` |
| PUT | `/security/v1/platform/modules/{moduleKey}/catalog` | `security.module.manage` |

### 17.4 Tenant membership/onboarding APIs

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

Recipient acceptance is a separate authenticated onboarding operation and does not require an administrator
permission.

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

Privileged standard roles use the maker-checker flow rather than immediate assignment.

### 17.7 Permission/template discovery

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/permissions` | `security.permission.read` |
| GET | `/security/v1/admin/tenants/{tenantId}/module-role-templates` | `security.permission.read` |

### 17.8 Location/schedule/device/policy APIs

These public routes expose the existing Phase 5 internal administration services.

They MUST use the exact permission keys defined in section 6 and MUST preserve current validated persistence
behavior rather than introducing a new read/write model.

### 17.9 Privileged approval APIs

| Method | Path | Permission |
|---|---|---|
| GET | `/security/v1/admin/tenants/{tenantId}/privileged-access-requests` | `security.privileged_access.approve` |
| POST | `/security/v1/admin/tenants/{tenantId}/privileged-access-requests/{requestId}/approve` | `security.privileged_access.approve` |
| POST | `/security/v1/admin/tenants/{tenantId}/privileged-access-requests/{requestId}/reject` | `security.privileged_access.approve` |

---

## 18. Database extension plan

Create a new migration. Do not edit v1.3 baseline migration.

Target migration:

```text
migrations/0002_security_admin_control_plane_v1.4.sql
```

### 18.1 Platform role/authentication tables

Add:

```text
security.platform_roles
security.platform_role_permissions
security.platform_user_role_assignments
security.local_user_credentials
```

`local_user_credentials` stores only a password hash, never plaintext.

### 18.2 Module catalogue tables

Add:

```text
security.modules
security.module_role_templates
security.module_role_template_permissions
security.role_template_bindings
```

Extend permission lifecycle to support:

```text
ACTIVE
DEPRECATED
RETIRED
```

The migration may add catalogue display/version metadata to `security.permissions` as required by the final DDL.

### 18.3 Group tables

Add:

```text
security.groups
security.group_memberships
security.group_role_assignments
```

Recommended state values:

```text
groups: ACTIVE | INACTIVE
group memberships: ACTIVE | ENDED
group role assignments: ACTIVE | ENDED
```

No nested-group relationship table is created.

### 18.4 Invitation/onboarding tables

Add:

```text
security.tenant_invitations
```

The invitation stores an immutable proposed-access snapshot sufficient to materialize roles/groups/location
assignments after acceptance/approval.

Invitation lifecycle:

```text
PENDING
ACCEPTED
CANCELLED
EXPIRED
REJECTED
```

### 18.5 Privileged-access tables

Add:

```text
security.privileged_access_requests
```

Lifecycle:

```text
PENDING
APPROVED
REJECTED
CANCELLED
EXPIRED
```

The record stores requester, subject user, Tenant, requested privileged role(s), approver, decision timestamp,
and correlation ID.

### 18.6 Structured administration audit

Add a structured administration change record rather than inventing uncontrolled free-text
`security_events.event_type` values.

Target table:

```text
security.admin_change_records
```

Minimum fields:

```text
admin_change_id
correlation_id
scope_type              PLATFORM | TENANT
tenant_id               nullable for Platform scope
actor_user_id
operation_key
resource_type
resource_id
outcome                 SUCCESS | DENIED | FAILED
before_state_json
 after_state_json
occurred_at_utc
```

Every successful Security Admin mutation must have a corresponding structured change record.

Denied/failed administrative authorization must remain traceable by correlation ID.

---

## 19. JWT contracts

### 19.1 Tenant USER token

Existing Verigence Tenant access JWT remains the runtime business token.

Important claims include:

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

`permissions[]` is authoritative for DI/WPM authorization.

Groups and module templates do not need to be exposed to business modules as authorization claims.

### 19.2 Platform Admin token

Platform Admin token uses a separate audience:

```text
verigence-security-admin
```

It contains Platform roles and Platform `security.*` permissions.

It contains no Tenant business access context.

### 19.3 Cross-module rule

DI/WPM must accept only the appropriate normal Security business token for business APIs.

They must not treat a Platform Admin token as a substitute for a Tenant business token.

---

## 20. Tenant isolation rules for Admin APIs

1. every Tenant Admin route includes `{tenantId}`;
2. caller's Security token Tenant must match `{tenantId}`;
3. Platform token is not accepted on Tenant USER Admin routes unless an explicitly designed Platform endpoint
   performs that operation;
4. all Tenant repository mutations are Tenant-scoped;
5. cross-Tenant identifiers must not be accepted merely because the UUID exists;
6. group, role, user, location, schedule, device, and invitation relationships must be validated inside the same
   Tenant;
7. CI must include negative cross-Tenant tests for every administration resource family.

---

## 21. Security rules for module catalogue changes

1. catalogue update requires `security.module.manage`;
2. request is correlated and audited;
3. module namespace is validated before DB mutation;
4. template references must exist in the submitted/current module permission catalogue;
5. active Tenant roles are not silently changed;
6. retirement of a permission referenced by effective Tenant roles is rejected or held at `DEPRECATED` until
   explicit migration;
7. Security reports affected Tenant roles before template/permission retirement;
8. module catalogue updates never grant a permission directly to a user;
9. Tenant Admins may consume registered permissions/templates but cannot create arbitrary new permission keys;
10. module catalogue history/version must remain traceable.

---

## 22. No-silent-change rules

The following are explicitly prohibited:

- changing effective Tenant permissions because a module template changed upstream;
- adding new permissions to existing Tenant roles without a Tenant/Platform administration action;
- assigning a privileged admin role without maker-checker approval;
- activating an invited Tenant member without human acceptance;
- granting a location through group membership;
- accepting a Platform Admin token as DI/WPM Tenant access;
- module runtime authorization based on role names;
- plaintext password storage;
- hard-coding the DEV bootstrap password in Git or an image;
- mutating the immutable v1.3 baseline migration;
- inventing device BLOCKED/REVOKED semantics before that decision is frozen;
- enabling Tenant activation before the activation prerequisite catalogue is complete.

---

## 23. Implementation sequence

The current Phase 5 internal services are retained. The next implementation is the Admin Control Plane, not Phase
6 machine actors.

### Increment A — v1.4 schema and standard catalogue

Implement:

- migration `0002_security_admin_control_plane_v1.4.sql`;
- `security.*` permission seeds;
- standard Platform roles;
- standard Tenant administrative role seeding logic;
- group/module/invitation/approval/audit persistence.

Definition of done:

- migration passes on real Neon;
- baseline v1.3 remains byte-identical;
- all FK/unique/check constraints validated;
- rollback/duplicate safety covered.

### Increment B — Platform Super Admin bootstrap and login

Implement:

- environment-secret bootstrap;
- Argon2id password hashing;
- first-login password change;
- Platform Admin JWT;
- Platform Tenant create/list/get/update;
- first Tenant Owner invitation creation.

Definition of done:

- plaintext bootstrap password absent from repo, DB, logs, test snapshots;
- bootstrap cannot overwrite existing account;
- wrong password fails closed;
- Platform Admin token rejected by DI business API;
- Tenant created as `CONFIGURING`.

### Increment C — Module catalogue API + DI initial synchronization

Implement:

- module registration/catalogue APIs;
- DI 28-permission import;
- DI five USER role templates;
- template provenance/version;
- atomic update and namespace validation;
- impact calculation.

Definition of done:

- DI cannot publish outside `di.*`;
- existing Tenant role is unchanged by a template update;
- explicit template upgrade changes role permissions and affected USER authorization versions;
- real Neon validation.

### Increment D — Groups and effective RBAC

Implement:

- group CRUD;
- group membership;
- group-role assignment;
- direct + group role resolution;
- authorization-version increments.

Definition of done:

- no nested groups;
- no direct group permission;
- no group-derived location;
- effective permissions equal union of direct/group roles;
- cross-Tenant group relationships rejected.

### Increment E — Tenant role Admin APIs

Expose:

- role CRUD;
- permission assignment/removal;
- template application/upgrade;
- direct user-role assignment.

Definition of done:

- reserved admin role keys protected;
- only registered ACTIVE permissions assignable;
- privileged role assignments route through maker-checker;
- affected authorization versions increment.

### Increment F — Team-member invitation and acceptance

Implement:

- invitation creation/cancel/list;
- recipient acceptance;
- external identity binding;
- PENDING -> ACTIVE membership transition;
- materialization of approved roles/groups/locations.

Definition of done:

- no membership activation before acceptance;
- invitation cannot be claimed twice;
- cross-user/external-identity rebinding blocked;
- expired/cancelled invitation cannot activate membership.

### Increment G — Privileged-access maker-checker

Implement:

- privileged request creation;
- approve/reject;
- no self-approval;
- role materialization after approval;
- audit records.

### Increment H — Expose existing Phase 5 policy/access Admin services

Expose the already-tested internal services for:

- Security Policy;
- Retention Policy;
- locations;
- schedules/windows;
- explicit user-location assignment;
- device listing/approval.

Device block/revoke mutations remain gated on the separate semantics decision.

### Increment I — DI alignment

In `verigence/verigence-di`:

- align actor type with `SERVICE_INTEGRATION`;
- fail closed on unknown actor type;
- align Tenant-scoped SYSTEM token handling;
- normalize Tenant path parameters;
- enforce exact permissions on all 54 operations;
- add cross-Tenant negative authorization tests;
- update stale Clerk-direct documentation.

### Increment J — Security -> DI E2E

Prove:

```text
Platform Super Admin
  -> creates Tenant
  -> synchronizes DI catalogue
  -> invites Tenant Owner
  -> Owner accepts
  -> Tenant role/group configured
  -> user receives Security JWT
  -> DI verifies Security JWKS
  -> DI allows operation with required di.* permission
  -> DI denies operation without permission
  -> DI denies cross-Tenant URL
```

Railway/Neon deployed E2E is required before this control-plane phase is marked complete.

---

## 24. Required test matrix

At minimum, CI/Neon/deployed tests must prove:

1. Platform bootstrap occurs only when permitted and no Super Admin exists.
2. bootstrap password is hashed and never logged/stored plaintext.
3. first-login password change is enforced.
4. Platform Admin JWT cannot be used as DI Tenant JWT.
5. non-Super-Admin cannot create a Tenant.
6. new Tenant is `CONFIGURING`.
7. module namespace ownership is enforced.
8. DI catalogue sync registers the exact reviewed permission set.
9. template update does not silently mutate Tenant roles.
10. Tenant Admin cannot create an arbitrary unregistered permission.
11. group cannot contain a group.
12. group cannot assign location.
13. direct + group role permissions resolve correctly.
14. RBAC changes increment affected authorization versions.
15. invitation does not activate before recipient acceptance.
16. cancelled/expired invitation cannot activate.
17. privileged role cannot activate without second-person approval.
18. requester cannot approve own privileged request.
19. cross-Tenant role/group/member relationships are rejected.
20. every admin mutation records correlation/audit evidence.
21. DI fails closed on unknown Security actor type.
22. DI accepts the canonical `SERVICE_INTEGRATION` actor type where applicable.
23. DI enforces token Tenant == URL Tenant for every Tenant router.
24. every DI route enforces its declared permission contract.
25. end-to-end Security JWT permissions drive DI authorization without a runtime Security DB/API lookup.

---

## 25. Explicitly deferred items

The following are not silently solved by this document:

- final `BLOCKED` versus `REVOKED` device business distinction;
- complete Tenant activation prerequisite catalogue;
- live Clerk invitation/provider API orchestration;
- SYSTEM/SERVICE_INTEGRATION machine credential issuance/synchronization automation;
- WPM permission/template catalogue until WPM is reviewed;
- nested groups;
- negative/deny permissions;
- group-derived location/schedule access;
- automatic mutation of existing Tenant roles when a module template changes;
- production bootstrap credential/value.

Each requires either an already-approved source or a later versioned decision.

---

## 26. Implementation recovery rule

After a context reset, read in this order before Admin Control Plane implementation:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
3. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`;
4. `docs/PHASE_5_SECURITY_ADMINISTRATION.md`;
5. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`;
6. current Security `dev` HEAD and active PRs;
7. for DI integration, current DI `dev` HEAD and:
   - `backend/src/verigence/di/auth/permissions.py`;
   - `backend/src/verigence/di/auth/verifier.py`;
   - `backend/src/verigence/di/auth/dependencies.py`;
   - `DI_MASTER_REFERENCE.md`.

Do not reconstruct this control-plane design from chat history after the document is merged.

---

## 27. Final design summary

```text
                            VERIGENCE SECURITY
                                   |
               +-------------------+-------------------+
               |                                       |
        PLATFORM CONTROL PLANE                   TENANT CONTROL PLANE
               |                                       |
     Platform Super Admin                         Tenant Owner/Admins
     Platform Security Admin                            |
     Module Catalog Admin                               +-- Members
     Platform Auditor                                   +-- Groups
               |                                        +-- Tenant Roles
               |                                        +-- Locations/Schedules
        Module Catalogue                                +-- Devices/Policies
               |                                              |
       +-------+-------+                                      |
       |               |                                      |
      DI              WPM                              Effective Roles
 Permissions      Permissions                                |
 Templates        Templates                                 v
       |               |                             Effective Permissions
       +-------+-------+                                      |
               |                                              v
               +-------------------------------------- Security USER JWT
                                                              |
                                            +-----------------+----------------+
                                            |                                  |
                                            v                                  v
                                           DI                                 WPM
                                    checks di.* permission             checks wpm.* permission
```

The central rule is simple:

> Modules define capabilities and optional templates. Security owns authoritative Tenant roles, groups,
> assignments, effective permissions, administrators, onboarding, and tokens. Modules authorize locally from
> the Security JWT permissions claim.
