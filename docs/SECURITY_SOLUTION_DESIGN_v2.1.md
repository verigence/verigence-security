# Verigence Security — Solution Design UC02 Revision

**Version:** 2.1  
**Status:** DESIGN REVISION FOR UC02 IMPLEMENTATION  
**Date:** 2026-08-21  
**Repository:** `verigence/verigence-security`  
**Target branch:** `dev`  
**Base design:** `docs/SECURITY_SOLUTION_DESIGN_v2.0.md` dated 2026-08-19  
**Related UC02 decision record:** `docs/SECURITY_UC02_ADMIN_OPERATION_ALIGNMENT.md`

> This document is a controlled revision of Security v2.0 for UC02 — Project Onboarding & Administration. All v2.0 requirements remain authoritative unless this document explicitly supersedes them. No application-code or migration change is authorized by this document.

---

## 1. UC02 scope and terminology

The user-facing UC02 concept is **Project**. Security continues to own the canonical internal **Tenant** entity and `tenant_id` authorization boundary.

For UC02:

```text
Web UI "Project"
    = one Security Tenant
    = one Audit Core Project projection
    = the same canonical tenant_id used by DI
```

The browser does not display or ask the SuperAdmin to enter a Tenant Code.

Security remains responsible for:

- canonical Tenant identity and lifecycle;
- global USER identity;
- operating-role assignment per Tenant;
- Tenant role bundles and functional authorization;
- human and ServiceIntegration token models;
- Security-owned administrative audit history.

Security does **not** own Dealer, Dealer Outlet, Customer, Journey or business-scope assignment.

---

## 2. UC02 administrative actor propagation

### 2.1 Two operation types

The Security v2.0 human-versus-machine separation remains in force and is clarified for UC02.

#### Human administrative operation

Examples include:

- create Project/Tenant;
- update Tenant administrative metadata;
- activate Project/Tenant;
- hard-delete Project/Tenant as part of Phase-1 rollback;
- assign/change/remove a Tenant operating role;
- other Security administrative operations.

For UC02 the browser calls Audit Core as its backend boundary. When Audit Core must invoke a Security administrative API for the same SuperAdmin action, Audit Core SHALL pass through the **same Security-issued human Bearer token** received from the browser.

Security SHALL:

1. validate that human JWT using the canonical Security human-token rules;
2. resolve the original global USER;
3. apply live Security authorization and SuperAdmin/admin-scope rules;
4. record that human USER as the authoritative actor.

Audit Core SHALL NOT replace the human token with a `ServiceIntegration` token and SHALL NOT mint an impersonated/delegated human token for these administrative calls.

#### Machine/integration operation

Normal module-to-module/background work and `/security/v1/authorization/check` continue to use the existing Security-issued `ServiceIntegration` model.

`ServiceIntegration` remains invalid for human-admin-only endpoints.

### 2.2 UC02 does not require a Web BFF

Security v2.0 permits a Web BFF capability in the Web module. UC02 does not require that capability for Project administration.

The approved UC02 path is:

```text
Browser
  -> Audit Core using Security human JWT
       -> Security ADMIN API using the same human JWT
       -> DI ADMIN API using the same human JWT where DI owns the admin operation
       -> Security authorization/check using ServiceIntegration for normal resource-server authorization
       -> DI normal integration using ServiceIntegration for normal document processing
```

This UC02-specific decision does not remove the general Web BFF capability from Security v2.0 for unrelated use cases.

---

## 3. Tenant creation for Project onboarding

### 3.1 Canonical identity

Security creates the canonical Tenant first and returns the generated `tenant_id`. Audit Core uses that exact ID for its Project projection and DI uses that exact ID for Tenant-scoped data/configuration.

### 3.2 Tenant Code is server-generated

The v2.0/current create shape that expects a caller-provided `tenantCode` is superseded for UC02.

For new UC02 Tenant creation:

- the caller supplies the business Tenant/Project name required by Security;
- Security generates the internal Tenant Code using a server-side convention;
- Tenant Code is stable after creation;
- Tenant Code format is an internal implementation convention, not a user-facing contract;
- uniqueness is enforced by Security;
- the generated Tenant Code may be returned for administration/diagnostics but is not entered in the Project form.

No Project OEM, Product Category, Dealer or Outlet fields are stored in Security merely to support UC02.

### 3.3 Initial lifecycle

A newly created UC02 Tenant remains in the existing `CONFIGURING` lifecycle until Project Readiness passes and activation is requested.

Activation remains an explicit Security lifecycle operation and SHALL be invoked under the same initiating human SuperAdmin identity propagated by Audit Core.

---

## 4. Employee and operating-role model

No new `Employee-in-Project-without-role` Security entity is introduced for Phase 1.

The existing target operating-role assignment remains the persisted Project association:

```text
(user_id, tenant_id) -> exactly one ACTIVE operating role
```

Approved operating roles remain:

- `PC`
- `TL`
- `PM`
- `CRM`
- `Executive`

The existing one-active-PM-per-Tenant invariant remains unchanged.

The UC02 Employees screen may search/select an approved global USER, but no new Security relationship exists until Role Mapping saves the operating-role assignment.

Removing the operating role removes Tenant authorization only. It SHALL NOT delete the global USER.

---

## 5. Dealer and Dealer Outlet business-scope correction

Security v2.0 Sections 2.8, 4.3 and 23 treated Dealer/Outlet as one Phase-1 assignment concept. That assumption is superseded for UC02.

Audit Core owns a real hierarchy:

```text
Project/Tenant
  -> Dealer
      -> Dealer Outlet
```

Security still stores **neither Dealer IDs nor Dealer Outlet IDs**.

The confirmed UC02 business-scope rules are:

```text
PC        -> specific Dealer Outlet(s)
TL        -> selected Dealer(s), covering their Outlets
PM        -> whole Project/Tenant
CRM       -> selected Dealer(s) OR whole Project/Tenant
Executive -> whole Project/Tenant
```

Security owns only the operating role. Audit Core owns the Dealer/Outlet business assignment and enforces the business scope.

For Audit Core runtime access:

```text
ALLOW = Security functional authorization
        AND Audit Core business-scope authorization
```

UC02 adds one Audit Core readiness rule: every ACTIVE Dealer Outlet must have at least one ACTIVE PC mapping. Security does not enforce this Outlet staffing rule because Security does not own Outlet scope.

---

## 6. Phase-1 Tenant hard delete for Project rollback

### 6.1 Scope

UC02 Phase 1 intentionally supports hard deletion of a Tenant as the final step of a SuperAdmin whole-Project rollback, including when the Project had previously been activated.

This Tenant deletion is separate from the existing global USER maker/checker hard-delete workflow. It SHALL NOT delete global USER identities.

### 6.2 Owning orchestration

Audit Core is the browser-facing deletion orchestrator.

Security Tenant deletion is invoked **last**, only after Audit Core has established that DI-owned Project data and Audit Core-owned Project data have been removed according to their owning-module contracts.

High-level order:

```text
SuperAdmin
  -> Audit Core Project delete operation
       -> DI purge / zero-state verification
       -> Audit Core Project-owned delete / zero-state verification
       -> Security Tenant hard delete LAST
       -> final cross-module completion
```

Security SHALL NOT report a successful Tenant delete if its own Tenant-scoped Security cleanup fails.

### 6.3 Security Tenant delete effect

A successful Tenant hard delete removes Security-owned Tenant-scoped live state, including as applicable:

- Tenant record;
- Tenant operating-role assignments;
- Tenant role-bundle configuration;
- TenantAdmin assignments scoped only to that Tenant;
- role-aligned Tenant Group representation if persisted;
- other Security-owned Tenant-scoped live authorization/configuration records that depend on the Tenant.

It SHALL preserve:

- global USER rows and Clerk identity bindings;
- module-wide/platform-wide admin assignments unrelated to the deleted Tenant;
- Security administrative audit evidence required to prove the delete action.

No new Tenant-delete retention duration is invented by UC02. Existing Security audit-retention policy applies unless separately approved.

### 6.4 Authorization

Phase-1 Tenant hard delete is:

- human `SuperAdmin` only;
- platform-wide;
- denied to ordinary operating users, TenantAdmin, ModuleAdmin and ServiceIntegration unless a later explicit design changes that rule.

Phase 2 will replace broad rollback-oriented deletion with a more process-oriented lifecycle/maker-checker/retention model.

---

## 7. UC02 Security API surface

Existing target APIs remain:

```text
POST  /security/v1/platform/tenants
GET   /security/v1/platform/tenants
GET   /security/v1/platform/tenants/{tenantId}
PATCH /security/v1/platform/tenants/{tenantId}
POST  /security/v1/platform/tenants/{tenantId}/activate

GET    /security/v1/platform/users
GET    /security/v1/roles
PUT    /security/v1/tenants/{tenantId}/users/{userId}/operating-role
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

UC02 modifies/adds:

### 7.1 Tenant create contract

```text
POST /security/v1/platform/tenants
Authorization: Bearer <Security-issued human SuperAdmin JWT>
```

UC02 rule: `tenantCode` is not caller input. Security generates it.

All other existing Security-owned validation that does not conflict with this rule remains unchanged.

### 7.2 Tenant hard delete

```text
DELETE /security/v1/platform/tenants/{tenantId}
Authorization: Bearer <Security-issued human SuperAdmin JWT>
```

Contract requirements:

- human SuperAdmin only;
- `ServiceIntegration` rejected;
- retry-safe/idempotent in effect for the Audit Core rollback orchestrator;
- global USERs preserved;
- Tenant-scoped Security authorization/configuration removed;
- Security audit event records actor, tenant, correlation and outcome;
- Security is the last owning module deleted in the whole-Project operation.

The exact transport response/status shape is finalized in the Security implementation/OpenAPI work and SHALL follow existing Security error-envelope/concurrency conventions rather than inventing a second error model.

---

## 8. Audit requirements

Security authoritative audit history for UC02 SHALL include at minimum:

- Tenant created, with generated Tenant Code recorded as safe metadata;
- Tenant metadata updated;
- Tenant activated;
- operating role assigned/replaced/removed;
- Tenant hard-delete attempt and outcome;
- initiating global USER identity for every administrative operation;
- correlation identifier received from Audit Core where supplied.

Bearer tokens, credentials and secrets are never written to audit/log records.

---

## 9. Phase-1 verification requirements

Before UC02 can rely on Security, tests SHALL prove:

1. caller cannot provide/override Tenant Code;
2. generated Tenant Code is unique and stable;
3. Project/Tenant creation is denied to `ServiceIntegration`;
4. forwarded valid SuperAdmin human JWT is accepted on Security admin APIs;
5. downstream actor recorded by Security is the original human SuperAdmin;
6. one operating role per USER/Tenant and one PM per Tenant remain enforced;
7. removing a Tenant operating role does not delete the global USER;
8. Tenant delete by non-SuperAdmin is denied;
9. Tenant delete by ServiceIntegration is denied;
10. Tenant delete removes Tenant-scoped Security state but preserves global USERs;
11. retry after an interrupted Audit Core rollback does not create duplicate Security effects;
12. no Dealer/Outlet identifier is persisted in Security to satisfy UC02 business scope.

---

## 10. Phase-2 notes

Deferred from Phase 1:

- process-oriented Project/Tenant deletion approval/maker-checker/retention policy;
- reuse/pick-existing Product Master capability, which is an Audit Core concern;
- stricter published-master effective-period overlap governance;
- any new Security membership construct separate from operating-role assignment;
- Dealer/Outlet staffing ratios beyond the Audit Core Phase-1 PC coverage readiness rule.

---

## 11. Supersession map

For UC02, this v2.1 revision supersedes the following v2.0 assumptions where they conflict:

- caller-supplied Tenant Code for Project onboarding;
- Dealer and Outlet being one business-scope entity;
- absence of a Tenant hard-delete rollback API;
- use of a machine actor for an administrative operation merely because Audit Core is calling Security on behalf of the browser;
- need for a Web BFF specifically for UC02 Project administration.

All other Security v2.0 identity, authentication, authorization, USER lifecycle, role-bundle, ServiceIntegration and audit rules remain in force.