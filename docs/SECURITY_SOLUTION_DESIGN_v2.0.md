# Verigence Security — Consolidated Solution Design

**Version:** 2.0  
**Status:** DRAFT FOR REVIEW  
**Date:** 2026-08-19  
**Repository:** `verigence/verigence-security`  
**Target branch:** `dev`  

> This document defines the target Phase-1 Security architecture from the confirmed requirements supplied for the redesign. It is intentionally independent of conflicting implementation choices already present in the repository. Existing Security, Audit Core and DI implementation/design were reviewed only to identify reusable components, integration boundaries and current-to-target gaps. No implementation change is authorized by this document until the design is reviewed and approved.

---

## 1. Purpose and scope

This document is the proposed consolidated Security design for the Verigence platform.

It covers:

- global human USER identity;
- Clerk-based human authentication;
- the Phase-1 human token model;
- USER onboarding and approval;
- USER lifecycle, suspension and hard deletion;
- USER role classifications and assignment rules;
- administrative-role rules;
- `TestUser`;
- role-aligned operating Groups;
- module permission catalogues;
- platform default and Tenant-specific role-to-permission mapping;
- synchronous runtime authorization;
- BFF/API-layer responsibilities within the Web module;
- Security integration with Audit Core and DI;
- Security audit requirements;
- target APIs and conceptual data model;
- current-to-target gap analysis;
- migration and Phase-1 implementation sequence.

This document does **not** authorize application-code changes.

### Design labels used in this document

- **CONFIRMED** — supplied and approved as part of the redesign requirements.
- **EXISTING AND RETAIN** — already implemented/design-aligned and useful in the target.
- **EXISTING BUT MODIFY** — useful existing capability whose semantics or implementation must change.
- **RETIRE** — must not participate in the target Phase-1 runtime model.
- **DEFERRED** — deliberately outside Phase 1.
- **OPEN DECISION** — insufficient confirmed information; this document does not invent the answer.

---

## 2. Confirmed Phase-1 requirements

### 2.1 Global human identity — CONFIRMED

All human users are employees of the company.

A human USER is onboarded once globally into Verigence.

Human onboarding is independent of:

- Tenant;
- Project;
- operating role;
- administrative role;
- Dealer;
- Outlet.

One person has one global Verigence USER identity. The same USER may later receive authorization in zero, one or multiple Tenants without creating another Verigence USER or Clerk account.

### 2.2 Authentication — CONFIRMED

Clerk owns human authentication.

Phase 1:

- uses Clerk first-party session JWTs for Web/Mobile authentication;
- has no MFA requirement;
- does not make Verigence Security a second human JWT issuer;
- does not store or validate human passwords in Verigence Security;
- does not make Clerk authoritative for Verigence roles or permissions.

### 2.3 Authorization — CONFIRMED

Verigence Security is the sole source of truth for functional authorization.

For Phase 1, every protected backend business request requiring Verigence authorization uses Security's authorization service.

The authorization request is **not OAuth token introspection**. The Clerk JWT proves authenticated identity; Security independently decides whether that USER may perform the requested Verigence function.

Phase 1 therefore has:

- no custom Verigence human JWT;
- no human permission claims copied into Clerk JWT;
- no distributed Security authorization projection in Audit Core/DI;
- no authorization event replication for normal runtime authorization;
- no opaque-token introspection design;
- no permission-epoch/revocation design for a Verigence-issued USER token.

Authorization fails closed when Security cannot make the required decision.

### 2.4 Operating roles — CONFIRMED

The global operating-role catalogue is:

- `PC`
- `TL`
- `PM`
- `CRM`
- `Executive`

Roles are USER role classifications. They are not independent role objects created by each Tenant.

A USER may have different operating roles in different Tenants, for example:

```text
USER U100
  Tenant A -> PC
  Tenant B -> TL
  Tenant C -> PM
```

Within one Tenant, a USER may have exactly one active operating role from `PC/TL/PM/CRM/Executive`.

There shall be exactly one active `PM` per Tenant.

`Executive` is Tenant-wide.

### 2.5 Administrative roles — CONFIRMED

Current administrative classifications are:

- `ModuleAdmin`
- `TenantAdmin`

`SuperAdmin` exists and is superior, but its detailed powers are deferred except where explicitly confirmed by this design.

Administrative roles may coexist with administrative roles:

```text
ModuleAdmin + TenantAdmin = valid
SuperAdmin + ModuleAdmin = valid
SuperAdmin + TenantAdmin = valid
```

Administrative and operating personas are mutually exclusive at global USER level.

Therefore the same USER cannot simultaneously hold an administrative role and any of:

- `PC`
- `TL`
- `PM`
- `CRM`
- `Executive`

This is a global USER-level restriction, not merely a same-Tenant restriction.

### 2.6 TestUser — CONFIRMED

A dedicated `TestUser` classification is required in Phase 1.

It must receive deliberately limited privileges suitable for controlled testing. Its exact permission bundle must not be invented before the functional permission catalogue is reviewed.

### 2.7 Dealer assignment — CONFIRMED

Dealer assignment is not Security RBAC.

Dealer assignment belongs to Audit Core and remains independent of:

- global USER identity;
- role definition;
- role-to-permission mapping.

The business model expects Dealers to have relevant `PC`, `TL`, `PM` and `CRM` users associated with them.

Phase 1 must **not** enforce staffing/cardinality rules such as:

- how many Dealers one PC covers;
- how many Dealers one TL covers;
- how many Dealers one PM covers;
- how many Dealers one CRM covers;
- how many users of each role a Dealer requires.

Those rules are deferred.

`Executive` is Tenant-wide and does not require Dealer assignment.

### 2.8 USER lifecycle — CONFIRMED

Phase-1 statuses are:

```text
PENDING
   ├── REJECTED
   └── ACTIVE
          ├── SUSPENDED
          └── deletion requested
                 ↓
              DISABLED
                 ↓
         SuperAdmin hard delete
```

`DISABLED` means the live account has been disabled because deletion has been requested.

`DELETE` is not another USER status. DELETE means actual hard deletion of the USER account.

Hard deletion uses maker/checker:

- deletion may be initiated by the USER themselves, Executive, TenantAdmin or ModuleAdmin;
- the maker action disables the USER;
- only SuperAdmin may execute the final hard delete.

### 2.9 Web BFF/API layer — CONFIRMED

The BFF/API capability is implemented as part of the **Web module**. It is not a separate Verigence module or separately owned business service.

The Web BFF may:

- provide UI-oriented APIs;
- route requests;
- orchestrate UI operations spanning Security and Audit Core;
- shield the Web client from backend service topology.

The Web BFF must not own:

- USERs;
- USER lifecycle;
- roles;
- permissions;
- Tenant authorization;
- Dealer assignments;
- authorization decisions as source of truth.

The exact Mobile access path is not changed by this observation and must not be inferred from the Web BFF decision.

---

## 3. Target platform architecture

```text
                         HUMAN USER
                        /          \
                       /            \
              Web application      Mobile client
              + Web BFF/API             |
                    |                    |
             Clerk authentication / session JWT
                    |                    |
                    +---------+----------+
                              |
             +----------------+----------------+
             |                |                |
             v                v                v
        +-----------+    +-------------+   +-----------+
        | SECURITY  |    | AUDIT CORE  |   |    DI     |
        |           |    |             |   |           |
        | USER SoT  |    | Dealer/     |   | generic   |
        | AuthZ SoT |    | business    |   | document  |
        | roles     |    | scope       |   | intel.    |
        | perms     |    | journeys    |   |           |
        +-----------+    +------+------+   +-----------+
                               |
                               | internal DI use also allowed
                               +---------------------------->
```

Human access to DI is allowed when DI exposes a human-facing protected capability. DI remains outside human onboarding.

### 3.1 Core ownership rule

```text
Clerk       = authenticate the human
Security    = identify the Verigence USER and decide functional authorization
Audit Core  = decide Dealer/business scope and execute Audit business logic
DI          = generic document-intelligence service; may serve authorized humans directly but owns no human onboarding
Web BFF     = client-facing composition/orchestration inside the Web module only
```

---

## 4. Trust boundaries

### 4.1 Clerk boundary — CONFIRMED

Clerk owns:

- credential verification;
- email/sign-up authentication functions provided by Clerk;
- Clerk session lifecycle;
- Clerk session JWT signing and public-key/JWKS publication.

Verigence Security owns the mapping from authenticated Clerk subject to global Verigence USER.

Clerk Organizations, Clerk roles and Clerk custom permission claims must not become the Verigence authorization source of truth.

### 4.2 Security boundary — CONFIRMED

Security owns:

- global USER record and status;
- Clerk-to-Verigence identity mapping;
- Tenant entity and Tenant lifecycle capability;
- global role classifications;
- USER role assignments;
- role-aligned operating Groups;
- module permission catalogue registry;
- platform default and Tenant-specific operating-role permission bundles;
- functional authorization decisions;
- Security administrative audit history.

### 4.3 Audit Core boundary — CONFIRMED

Audit Core owns Dealer/Outlet/business hierarchy and business assignment.

Security must not store Dealer IDs merely to make authorization convenient.

For a Dealer-scoped Audit operation:

```text
ALLOW = Security functional authorization
        AND
        Audit Core Dealer/business-scope authorization
```

### 4.4 DI boundary — CONFIRMED

Human users **may call DI directly** for approved DI capabilities.

DI has no role in human onboarding or human role assignment.

For a protected direct human DI request, DI follows the same Phase-1 human security model:

```text
Human -> DI with Clerk session JWT
DI validates Clerk JWT locally
DI -> Security authorization service for the required DI permission
Security -> ALLOW / DENY
DI executes only if allowed
```

Audit Core may also invoke DI internally for Audit workflows after its own applicable authentication, Security authorization and Audit Core business-scope checks.

---

## 5. Web BFF boundary

### 5.1 Responsibilities — CONFIRMED

The BFF capability is part of the Web module and provides a stable frontend-facing surface for the Web application.

Typical Web BFF functions include:

- user-management screens;
- pending/active user views;
- approval/rejection actions;
- role-assignment screens;
- Tenant/Dealer assignment orchestration;
- forwarding Clerk authentication context to backend APIs;
- response composition where one UI view needs Security and Audit Core data.

### 5.2 Non-responsibilities — CONFIRMED

The Web BFF does not persist authoritative copies of USER, role, permission or Dealer assignment records.

The Web BFF must not grant access merely because a UI control is shown or hidden.

Every backend module remains responsible for enforcing its own protected operation.

### 5.3 Deployment ownership — CONFIRMED

The BFF is **merged into the Web module**. No separate BFF Verigence module is introduced.

This design does not create an additional repository/service ownership boundary merely for the BFF capability.

---

## 6. Global USER model

### 6.1 USER is platform-global — CONFIRMED

Canonical relationship:

```text
Person
  -> one Verigence USER
  -> one active Clerk subject mapping
  -> zero or more Tenant-context authorization assignments
```

Tenant authorization never creates another USER.

### 6.2 Global uniqueness — EXISTING AND RETAIN

The existing global-onboarding design already treats email identity as globally unique for the initial email-based flow and protects against one Clerk subject being silently rebound to a different USER.

Those invariants remain useful and must be retained.

### 6.3 Tenant membership — RETIRE FROM RUNTIME AUTHORIZATION

A Tenant-membership record is not a prerequisite for human identity or runtime Tenant authorization.

Historical `tenant_memberships` data may remain for migration/audit compatibility, but target Phase-1 authorization must not depend on it.

---

## 7. Clerk authentication architecture

### 7.1 Human sign-in — CONFIRMED

Web/Mobile uses Clerk's first-party authentication/session model.

After successful Clerk authentication, the client obtains a Clerk session JWT.

The Clerk JWT proves authenticated identity. It does not by itself prove that:

- the Verigence USER is ACTIVE;
- the USER has authorization in a Tenant;
- the USER has a required Verigence permission;
- the USER has Dealer/business scope.

### 7.2 Local JWT validation — CONFIRMED

Backend boundaries receiving the Clerk session JWT validate it locally using Clerk public keys/JWKS.

Validation must include the applicable standard token checks, including signature, issuer and expiry, plus the configured audience/authorized-party checks supported by the selected Clerk first-party token configuration.

No network call to Clerk is required for ordinary JWT signature validation.

### 7.3 Security validates the identity presented to authorization — TARGET REQUIREMENT

When a backend module asks Security for an authorization decision, Security must independently validate the Clerk authentication evidence it is relying upon; it must not trust an arbitrary `userId` supplied by a client.

The original Clerk bearer token is therefore the canonical human authentication evidence for the Phase-1 authorization call.

---

## 8. Phase-1 human token model

### 8.1 One human token issuer — CONFIRMED

Clerk is the human session-token issuer.

Security does not issue a second human access JWT in Phase 1.

### 8.2 Authorization claims are not copied into Clerk — CONFIRMED

Do not place the authoritative Verigence role/permission model inside Clerk simply to make backend authorization local.

The Clerk session JWT should remain authentication evidence rather than a replicated Security authorization database.

### 8.3 No human-token introspection — CONFIRMED

Phase-1 protected backend calls do not introspect the Clerk JWT with Clerk.

The JWT is validated locally. Security is then called for the independent Verigence authorization decision.

### 8.4 Existing Security-issued human tokens — RETIRE

Current Security runtime contains human login/access-session paths that authenticate through Clerk Backend APIs and issue a Verigence access token. Those human-token issuance paths conflict with this Phase-1 target and must be retired from the active human flow after replacement is implemented.

Security signing/JWKS capability may remain where required for approved machine/service authentication; that is separate from the human token model.

---

## 9. Human USER onboarding

### 9.1 Principle — CONFIRMED

Onboarding creates a global identity only.

It does not assign:

- Tenant;
- operating role;
- administrative role;
- Dealer;
- Outlet.

### 9.2 Platform-global onboarding gate — EXISTING AND RETAIN

The existing platform-global onboarding-key concept is compatible with global USER onboarding and can remain the Phase-1 submission gate unless separately changed.

Possession of the onboarding key grants no application role, Tenant authorization or business access.

### 9.3 Target onboarding sequence

```text
1. Employee enters the global onboarding journey through Web/Mobile.

2. Security validates the permitted platform-global onboarding gate
   and duplicate global identity constraints.

3. A global Verigence onboarding request / USER candidate is created
   without Tenant, role, Dealer or Outlet assignment.

4. Clerk owns the credential/sign-up/email-authentication interaction.
   Verigence does not store or validate the employee password.

5. After successful Clerk authentication, the Clerk subject is bound
   to exactly one global Verigence USER after Security validates the
   expected identity/email relationship.

6. USER remains PENDING.

7. Authorized administration can list PENDING users.

8. Administrator changes the USER to ACTIVE or REJECTED.

9. Tenant/role/Dealer configuration is performed separately after
   identity onboarding.
```

### 9.4 Existing Security password/OTP façade — EXISTING BUT MODIFY

Current Phase-1 self-onboarding routes receive password/OTP inputs and broker Clerk operations from Security. This is not required by the new first-party Clerk session model and should not be treated as the target merely because it already exists.

The target onboarding UI/API contract must keep authentication credentials within Clerk-owned flows.

### 9.5 Onboarding failure rules

- wrong/disabled onboarding gate -> no active USER access;
- duplicate global email -> do not create another USER;
- Clerk identity mismatch -> do not bind;
- Clerk authentication success -> USER still remains PENDING until Verigence approval;
- PENDING/REJECTED USER -> authorization service denies protected application access.

---

## 10. USER lifecycle/status model

### 10.1 Canonical Phase-1 states — CONFIRMED

```text
PENDING
   ├── REJECTED
   └── ACTIVE
          ├── SUSPENDED
          └── DISABLED  (deletion requested)

DISABLED
   -> hard DELETE by SuperAdmin checker
```

### 10.2 Status semantics

| Status | Meaning |
|---|---|
| `PENDING` | Global identity exists/bound sufficiently for review but is not approved for Verigence application access. |
| `REJECTED` | Onboarding/approval was rejected. No protected application access. |
| `ACTIVE` | USER is eligible for authorization decisions, subject to role/Tenant/permission rules. |
| `SUSPENDED` | USER is temporarily non-active. Protected authorization fails. |
| `DISABLED` | Account is disabled because hard deletion has been requested and is awaiting SuperAdmin checker/execution. |

### 10.3 DELETE is not a status — CONFIRMED

Hard DELETE removes the live USER account after the maker/checker preconditions are met.

### 10.4 Reactivation transitions — OPEN DECISION

The following are not confirmed and must not be guessed:

- `SUSPENDED -> ACTIVE` approval rule;
- whether `REJECTED` can return to `PENDING` or `ACTIVE`;
- whether a deletion request can be cancelled and `DISABLED` returned to another status.

---

## 11. Approval and rejection

### 11.1 Pending list — CONFIRMED

Security must expose a filterable global USER list capable of returning PENDING users for approval review.

### 11.2 Activation — CONFIRMED

Clerk authentication alone never activates a Verigence USER.

Activation is an explicit Security lifecycle decision.

### 11.3 Rejection — TARGET REQUIREMENT

The target USER status model includes `REJECTED`; the current implementation does not expose it in the global status API and must be modified.

The Security audit trail records the approving/rejecting actor, target USER, timestamp and reason where supplied.

---

## 12. Suspension and session enforcement

### 12.1 Security status is authoritative — CONFIRMED

Every authorization decision first requires USER status `ACTIVE`.

A valid Clerk JWT presented by a `SUSPENDED`, `DISABLED`, `PENDING` or `REJECTED` USER is insufficient for Verigence access.

### 12.2 Clerk lifecycle synchronization — EXISTING AND RETAIN WITH MODIFICATION

Existing Security design already synchronizes non-active USER lifecycle to Clerk by terminating/banning authentication capability as a defense-in-depth measure.

Target Phase 1 should preserve that concept for `SUSPENDED` and `DISABLED`, while Security status remains the immediate Verigence authorization authority.

If Clerk lifecycle synchronization is temporarily unavailable, Security remains fail-closed because the local USER status is already non-ACTIVE.

---

## 13. Maker/checker hard deletion

### 13.1 Maker rule — CONFIRMED

Deletion request may be initiated by:

- the USER themselves;
- Executive;
- TenantAdmin;
- ModuleAdmin.

The maker action does not hard-delete immediately.

It transitions the USER to `DISABLED`, terminates application access and records the deletion request/audit evidence.

### 13.2 Checker rule — CONFIRMED

Only `SuperAdmin` may execute final hard deletion.

This is one of the explicitly confirmed SuperAdmin responsibilities in this design. SuperAdmin's broader authority remains deferred except for the permission-mapping responsibility confirmed in Section 21.

### 13.3 Two-operation API model — TARGET REQUIREMENT

Phase 1 keeps status change and hard deletion as separate operations.

**Maker/status operation:**

```text
PATCH /security/v1/users/{userId}/status
```

Conceptual deletion-request payload:

```json
{
  "status": "DISABLED",
  "reasonCode": "DELETE_REQUEST",
  "reason": "optional human-readable reason"
}
```

The same status operation may support other approved status transitions according to the caller's permission and lifecycle rules.

**Checker/hard-delete operation:**

```text
DELETE /security/v1/platform/users/{userId}
```

Preconditions include:

- target USER exists;
- target USER is `DISABLED` due to a recorded deletion request;
- caller is authorized as SuperAdmin under the final SuperAdmin model;
- deletion-request evidence is present;
- required maker/checker constraints pass.

### 13.4 Deletion workflow

```text
Maker
  |
  | request delete
  v
Security
  |
  +-- record deletion request + actor/time/reason
  +-- status -> DISABLED
  +-- revoke/terminate Verigence access
  +-- terminate/disable Clerk authentication sessions/account access
  |
  v
Await SuperAdmin checker
  |
  | hard DELETE
  v
Security deletion coordinator
  |
  +-- delete/retire Clerk live identity/account as required
  +-- remove live Security role/Tenant authorization assignments
  +-- remove live global USER identity/PII according to approved retention
  +-- release email for permitted reuse
  +-- preserve non-PII historical audit references/evidence
```

### 13.5 Multi-Tenant deletion authority — OPEN DECISION

A USER is global and may be authorized in several Tenants.

The scope under which an `Executive` or `TenantAdmin` may request global deletion of a USER who is active in other Tenants is not confirmed. The target API must not implement a guessed rule.

### 13.6 Maker/checker actor separation — OPEN DECISION

The requirement confirms maker/checker and SuperAdmin final execution, but does not explicitly define whether the final SuperAdmin must always be a different human from the maker in every edge case. This must be finalized before implementation.

### 13.7 Historical audit evidence — TARGET REQUIREMENT

Hard deletion of the live USER must not cascade-delete historical Security/Audit business evidence.

Historical events should retain an immutable actor reference/snapshot that does not require the live USER row to continue existing. Exact retention duration and PII-minimization rules remain subject to the final retention policy.

---

## 14. Role taxonomy

### 14.1 Global role catalogue — CONFIRMED

The role definition catalogue is global.

Target role classes:

| Classification | Role keys | Assignment nature |
|---|---|---|
| Operating | PC, TL, PM, CRM, Executive | Tenant-context assignment; exactly one operating role per USER/Tenant. |
| Administrative | ModuleAdmin, TenantAdmin, SuperAdmin | Administrative assignment; admin roles may stack but cannot coexist with any operating persona. |
| Test | TestUser | Controlled test access with deliberately limited privileges. |

### 14.2 Tenant does not create role identity — CONFIRMED

`PC` in Tenant A and `PC` in Tenant B are the same global role classification.

What differs by Tenant is the approved functional permission mapping.

### 14.3 Role names are not runtime permission checks — CONFIRMED

Business APIs authorize using required permission keys evaluated by Security.

The operating role may be returned for administration/audit/UI context, but modules must not replace permission checks with `if role == ...` logic.

### 14.4 Role-aligned Groups — CONFIRMED

Phase 1 includes a simple Group concept aligned 1:1 with the operating roles.

For each Tenant, the operating Groups are:

- `PC`
- `TL`
- `PM`
- `CRM`
- `Executive`

A Group is **not a second RBAC authority** and does not own a separate permission list.

The relationship is:

```text
Tenant role Group
      |
      v
same role_key
      |
      v
Tenant role permission bundle
```

For example:

```text
Tenant T1 / PC Group
        -> role_key = PC
        -> Tenant T1 PC permission bundle
```

Therefore Group and Role always expose the same effective permissions because the Group references the Role; Security does not maintain a separate `group_permissions` mapping.

Operating-role assignment is authoritative for Group membership. When a USER is assigned or changed to an operating role, the USER is automatically represented in the matching role Group for that Tenant.

```text
U100 + T1 -> PC
             |
             +-> member of T1 / PC Group
```

Changing `PC -> TL` moves the USER from the PC Group to the TL Group as part of the same logical assignment change.

The existing invariants therefore also govern Group membership:

- one active operating Group per USER/Tenant;
- exactly one active PM member in the PM Group per Tenant;
- admin/operating global exclusivity remains unchanged.

Arbitrary custom Groups, Group-specific permissions and Group-to-multiple-role inheritance are not part of the Phase-1 model.

---

## 15. Operating-role assignment rules

### 15.1 Cardinality — CONFIRMED

```text
UNIQUE active operating role per (user_id, tenant_id)
```

Valid:

```text
U100 + T1 -> PC
U100 + T2 -> TL
```

Invalid:

```text
U100 + T1 -> PC
U100 + T1 -> TL
```

### 15.2 Set/replace semantics — CONFIRMED

The operating-role API sets/replaces the USER's one role in that Tenant.

It must not be an additive role API that can accumulate `PC + TL`.

The corresponding role-aligned Group membership follows the role assignment automatically; Group membership does not independently add another role.

### 15.3 Exactly one PM per Tenant — CONFIRMED

Security enforces:

```text
maximum one ACTIVE operating-role assignment where role_key = PM per tenant_id
```

The implementation should enforce this transactionally at the database/application boundary so concurrent administrative requests cannot create two active PMs.

### 15.4 Different roles across Tenants — CONFIRMED

Changing a USER's role in one Tenant does not change their role in another Tenant.

---

## 16. Administrative-role rules

### 16.1 Admin/operating exclusivity — CONFIRMED

If a USER holds any administrative role, Security must reject assignment of any operating role to that USER.

If a USER holds any operating role in any Tenant, Security must reject assignment of an administrative role unless the operating assignment is first removed according to the approved administrative process.

### 16.2 Administrative-role stacking — CONFIRMED

`ModuleAdmin` and `TenantAdmin` may coexist.

`SuperAdmin` may coexist with `ModuleAdmin` and/or `TenantAdmin`.

### 16.3 Exact administrative scope — PARTIALLY CONFIRMED / OPEN

The role names imply module/Tenant/platform scopes and existing implementation contains platform/Tenant administrative models. However detailed `ModuleAdmin`, `TenantAdmin` and `SuperAdmin` permission bundles and assignment authority are not fully supplied in the redesign requirements.

Do not infer broad powers beyond permissions explicitly approved in the eventual role bundle.

### 16.4 SuperAdmin — PARTIALLY CONFIRMED / OTHERWISE DEFERRED

Detailed SuperAdmin privilege boundaries, bootstrap/initial-user design and subsequent SuperAdmin assignment process remain deferred.

Confirmed here:

- SuperAdmin is an administrative persona;
- it may coexist with other administrative roles;
- it cannot coexist with operating roles;
- only SuperAdmin executes final global USER hard deletion;
- SuperAdmin can review module permission catalogues and update the applicable Tenant role permission bundle.

No additional SuperAdmin privilege semantics are introduced by this revision.

Existing implementation granting `platform.super_admin` every active permission must not be treated as automatically approved target behaviour.

---

## 17. TestUser

### 17.1 Purpose — CONFIRMED

`TestUser` exists for controlled testing with deliberately limited privileges.

### 17.2 Permission bundle — OPEN DECISION

The exact TestUser permissions must be selected only after approved module permission catalogues are reviewed.

### 17.3 Role coexistence — SAFE PHASE-1 DEFAULT / OWNER REVIEW REQUIRED

To preserve the requirement that TestUser remains deliberately limited, the Phase-1 design should treat TestUser as isolated from administrative and operating personas unless explicitly approved otherwise.

This is a security-safe default but requires owner confirmation before implementation because exact coexistence rules were not separately stated.

---

## 18. Tenant-context role assignment

Tenant context is part of the assignment, not part of the role definition.

Conceptual target record:

```text
user_id
 tenant_id
 role_key
 status
 valid_from_utc
 valid_to_utc
 assigned_by_user_id
 assigned_at_utc
```

For operating roles the active uniqueness rule is `(user_id, tenant_id)` rather than `(user_id, tenant_id, role_id)`.

A role change replaces the active role assignment for that USER/Tenant and updates the USER's role-aligned Group membership as the same logical operation.

---

## 19. One-PM-per-Tenant invariant

Security must prevent two active PM assignments for one Tenant.

Conceptually:

```text
Tenant T1
  -> PM = U100
```

A request to assign `U200` as PM while `U100` remains active PM returns a conflict rather than creating a second PM.

The administrative UI/Web BFF may guide the user through replacing the PM, but Security owns and enforces the invariant.

The Tenant PM Group therefore also has at most one active member.

---

## 20. Permission catalogue ownership

### 20.1 Module-owned permission catalogue — CONFIRMED

Each module owns/publishes the functional capabilities it understands.

Security is the registry and authorization authority for those permission keys.

Examples of conceptual capabilities include document upload/delete, audit review and journey operations, but canonical strings must come from approved module catalogues rather than being invented by this design.

### 20.2 Permission discovery APIs — CONFIRMED

Security must provide APIs that allow an authorized administrator, including SuperAdmin, to discover the permissions currently available from each registered module.

The required logical flow is:

```text
Module publishes/registers its permission catalogue
        |
        v
Security stores the active module permission catalogue
        |
        v
SuperAdmin lists modules and available permissions
        |
        v
Security shows the Tenant's current role bundle
        |
        v
SuperAdmin keeps the default or changes selected permissions
        |
        v
The configured role is assigned to a USER
```

A role-permission mapping must reference permission keys that exist and are ACTIVE in the registered module catalogue. Security must not allow an arbitrary unregistered permission string to be mapped to a role bundle.

### 20.3 Existing module catalogue — EXISTING AND RETAIN

Current Security already provides a Platform Module Catalogue surface and persists module permissions/templates. This is aligned with the target and should be retained, subject to role-model changes described below.

### 20.4 Permission retirement — EXISTING AND RETAIN

Existing catalogue logic detects conflicts when a permission is still referenced by role configuration. That safety behaviour remains valuable.

---

## 21. Platform defaults and Tenant-specific role-to-permission mapping

### 21.1 Default-first model — CONFIRMED

SuperAdmin must not have to construct every operational role bundle from scratch when a Tenant is onboarded.

Security shall maintain platform default permission mappings for the operating roles where an approved default bundle exists.

When a new Tenant is initialized, Security copies/seeds those defaults into that Tenant's role permission configuration.

Conceptually:

```text
Platform default PC bundle
          |
          +---- seed ----> Tenant A / PC bundle
          |
          +---- seed ----> Tenant B / PC bundle
```

A later Tenant-specific change affects that Tenant's bundle only.

```text
Tenant A / PC bundle -> customized
Tenant B / PC bundle -> remains its own current bundle
```

SuperAdmin can review the registered module permissions and update the role definition's permission mapping for the given Tenant when required.

### 21.2 Stable role, Tenant-specific bundle — CONFIRMED

Conceptually:

```text
GLOBAL ROLE: PC

Platform default bundle:
  approved Audit Core + DI permissions

Tenant A bundle:
  seeded from default, then optionally customized

Tenant B bundle:
  seeded from default, then optionally customized
```

Tenant A does not create a new PC role object; it configures the functional bundle for the global `PC` classification.

The Tenant's role-aligned PC Group references exactly the same Tenant PC bundle.

### 21.3 Target data relationship

```text
role_definitions (global)
       |
       +-- platform_role_permission_defaults
       |      role_key
       |      permission_key
       |
       +-- tenant_role_permissions
              tenant_id
              role_key
              permission_key
```

Role-aligned Groups reference `role_key`; there is no separate Group-permission table.

### 21.4 Existing Tenant-created role objects — RETIRE/MODIFY

Current `security.roles` and `/admin/tenants/{tenantId}/roles` APIs create independent Tenant-owned role records. That model conflicts with the confirmed role-classification rule.

The target removes Tenant role creation for the fixed Phase-1 role catalogue.

### 21.5 Existing module role templates — EXISTING BUT MODIFY

Existing module role templates can remain reusable source material for platform default permission bundles, but they must not create a new business role identity per Tenant.

### 21.6 Approved default PC/TL/PM/CRM bundles — CONFIRMED FROM CURRENT AUDIT CORE BASELINE

The current Audit Core baseline already contains an approved default cross-module role-bundle document for `PC`, `TL`, `PM` and `CRM`. The permissions below are copied exactly from that approved baseline and are therefore the Phase-1 default seed for those roles.

#### PC default

**Audit Core**

- `audit.project.read`
- `audit.master.read`
- `audit.customer.read`
- `audit.customer.write`
- `audit.journey.create`
- `audit.journey.read`
- `audit.journey.update`
- `audit.journey.submit`
- `audit.evidence.read`
- `audit.evidence.upload`
- `audit.evidence.refresh`
- `audit.payment.read`
- `audit.payment.write`
- `audit.delivery.read`
- `audit.delivery.write`
- `audit.trade_in.read`
- `audit.trade_in.write`
- `audit.finding.read`
- `audit.finding.create`
- `audit.work.read`
- `audit.work.update`
- `audit.daily_ops.read`
- `audit.daily_ops.execute`

**DI**

- `di.subject.create`
- `di.subject.read`
- `di.document.upload`
- `di.document.read`
- `di.document.content.read`
- `di.document.fields.read`
- `di.document.quality.read`
- `di.entity_link.read`
- `di.entity_link.write`

**Guard:** PC receives no `audit.*.verify` capability and no `di.verification.write` in the approved default.

#### TL default

**Audit Core**

- `audit.project.read`
- `audit.master.read`
- `audit.customer.read`
- `audit.journey.read`
- `audit.evidence.read`
- `audit.evidence.refresh`
- `audit.payment.read`
- `audit.payment.verify`
- `audit.delivery.read`
- `audit.delivery.verify`
- `audit.trade_in.read`
- `audit.trade_in.verify`
- `audit.finding.read`
- `audit.finding.create`
- `audit.finding.update`
- `audit.review.read`
- `audit.review.decide`
- `audit.work.read`
- `audit.work.update`
- `audit.work.manage`
- `audit.daily_ops.read`
- `audit.daily_ops.review`
- `audit.escalation.read`
- `audit.analytics.read`

**DI**

- `di.subject.read`
- `di.document.read`
- `di.document.content.read`
- `di.document.fields.read`
- `di.document.quality.read`
- `di.verification.read`
- `di.verification.write`
- `di.operations.read`

#### PM default

**Audit Core**

- `audit.project.read`
- `audit.project.update`
- `audit.project.assignment.manage`
- `audit.master.read`
- `audit.customer.read`
- `audit.journey.read`
- `audit.evidence.read`
- `audit.evidence.refresh`
- `audit.payment.read`
- `audit.payment.verify`
- `audit.delivery.read`
- `audit.delivery.verify`
- `audit.trade_in.read`
- `audit.trade_in.verify`
- `audit.finding.read`
- `audit.finding.create`
- `audit.finding.update`
- `audit.finding.resolve`
- `audit.review.read`
- `audit.review.decide`
- `audit.work.read`
- `audit.work.update`
- `audit.work.manage`
- `audit.daily_ops.read`
- `audit.daily_ops.review`
- `audit.crm.read`
- `audit.crm.manage`
- `audit.escalation.read`
- `audit.escalation.manage`
- `audit.analytics.read`
- `audit.audit_trail.read`

**DI**

- `di.subject.read`
- `di.document.read`
- `di.document.content.read`
- `di.document.fields.read`
- `di.document.quality.read`
- `di.verification.read`
- `di.verification.write`
- `di.operations.read`

#### CRM default

**Audit Core**

- `audit.project.read`
- `audit.customer.read`
- `audit.journey.read`
- `audit.evidence.read`
- `audit.finding.read`
- `audit.work.read`
- `audit.work.update`
- `audit.crm.read`
- `audit.crm.execute`
- `audit.escalation.read`

**DI**

- `di.subject.read`
- `di.document.read`
- `di.document.content.read`
- `di.document.fields.read`
- `di.document.quality.read`

CRM is read-only in DI by default.

### 21.7 Executive default bundle — OPEN DECISION, NOT GUESSED

`Executive` is a confirmed operating role and has a role-aligned Tenant Group, but the current approved cross-module default-bundle document explicitly defines defaults only for `PC/TL/PM/CRM` and treats Executive separately.

This Security design therefore does not invent an Executive Audit Core/DI default permission list.

The Executive default bundle must be explicitly approved before it is seeded. Until then, Security must not silently infer a permission list from the role name.

### 21.8 TestUser default bundle — OPEN DECISION

The exact deliberately limited TestUser permission set remains open and is not inferred from the operational defaults.

### 21.9 Default seed and Tenant override flow — CONFIRMED

```text
Module permission catalogues registered in Security
        |
        v
Platform default role bundles available
        |
        v
Tenant created / initialized
        |
        v
Security seeds approved role defaults into Tenant role bundles
        |
        v
SuperAdmin reviews current Tenant role bundle
        |
        +-- no change -> assign role to USER
        |
        +-- change required
               |
               v
        GET module permissions
               |
               v
        update Tenant role bundle
               |
               v
        assign role to USER
```

Every Tenant-specific role-bundle change is an audited Security operation.

---

## 22. Runtime authorization

### 22.1 Security is the Policy Decision Point — CONFIRMED

For Phase 1, Security is synchronously called for every protected backend request requiring Verigence functional authorization.

Normal protected-resource flow:

```text
Client
  |
  | Clerk JWT
  v
Resource Server (Security / Audit Core / DI as applicable)
  |
  +-- validate Clerk JWT locally
  |
  +-- determine required canonical permission for endpoint/action
  |
  +-- call/use Security authorization service
  |      Clerk JWT + tenantId + required permission
  |
  |      Security:
  |        validate Clerk JWT
  |        Clerk sub -> global USER
  |        USER status == ACTIVE
  |        Tenant active where applicable
  |        resolve USER operating role
  |        resolve Tenant role permission bundle
  |        evaluate required permission
  |        return ALLOW/DENY + stable decision context
  |
  +-- if Audit Core, additionally evaluate Dealer/business scope where applicable
  |
  +-- execute operation
```

The role-aligned Group does not add permissions at runtime. It is the USER collection corresponding to the same operating role and same Tenant permission bundle.

### 22.2 Authorization API — TARGET

Conceptual internal API:

```text
POST /security/v1/authorization/check
Authorization: Bearer <Clerk session JWT>
```

Conceptual request:

```json
{
  "tenantId": "<tenant-id-or-null-for-platform-scope>",
  "permissionKey": "<canonical-permission-key>"
}
```

Conceptual response:

```json
{
  "allowed": true,
  "userId": "<global-verigence-user-id>",
  "decisionId": "<correlation/audit decision identifier>",
  "operatingRole": "PC"
}
```

`operatingRole` is context information only. The authorization decision is permission-based.

The final API contract may refine names/status codes, but must preserve these semantics.

### 22.3 No arbitrary user identity trust — TARGET

The authorization endpoint must not accept a client-provided `userId` as proof of identity.

It resolves the USER from verified Clerk authentication evidence.

### 22.4 Internal caller protection — TARGET

The authorization endpoint is an internal Security service boundary. It should be callable only by registered platform components/Web BFF paths according to the final service-authentication/network policy.

Exact machine credential mechanics for Security callers should reuse the approved platform service-identity mechanism rather than creating a second human token model.

### 22.5 Security's own admin APIs

Security administration endpoints do not make a network call back into Security. They use the same authorization decision logic in-process after validating the Clerk authentication context.

### 22.6 Failure rule — CONFIRMED

If Security is unavailable or cannot produce a trustworthy authorization decision, the protected backend operation fails closed.

No cached allow result is required in Phase 1.

### 22.7 Future optimization — DEFERRED

Do not introduce projections, local replicated permission stores, user-token permission claims or long-lived authorization caches until measured performance/availability shows a need.

---

## 23. Dealer assignment boundary

### 23.1 Security does not own Dealer assignment — CONFIRMED

Security authorization ends at the functional permission decision.

Dealer association is an Audit Core business assignment.

### 23.2 Phase-1 Dealer associations — CONFIRMED

Audit Core must be able to associate relevant operating users with Dealers:

- PC
- TL
- PM
- CRM

No Phase-1 cardinality ratio is enforced.

### 23.3 Executive — CONFIRMED

Executive is Tenant-wide and does not require Dealer assignment.

### 23.4 Outlet assignment — OPEN/DEFERRED

The redesign requirement confirms Dealer association but does not define a Phase-1 USER-to-Outlet restriction model. Security must not invent one.

### 23.5 Web BFF orchestration

A UI may present one assignment operation containing role and Dealer selection.

Web BFF orchestration may perform:

```text
1. Security: set USER/Tenant operating role
2. Audit Core: set/create Dealer association
```

Each system remains authoritative for its own write.

If Security succeeds and Dealer association fails, no Dealer-scoped business access is granted merely because the role exists; Audit Core fails its local business-scope check.

---

## 24. USER administration APIs

### 24.1 List/search global USERs — TARGET

Prefer one filterable API:

```text
GET /security/v1/platform/users
```

Supported query concepts:

- `status=PENDING|REJECTED|ACTIVE|SUSPENDED|DISABLED`
- text search on approved USER-identifying fields;
- pagination;
- deterministic sorting.

Required UI use cases include:

- pending approval list;
- active/approved user list;
- rejected list;
- suspended list;
- disabled/pending-hard-delete list.

### 24.2 USER detail — TARGET

```text
GET /security/v1/platform/users/{userId}
```

Returns Security-owned USER lifecycle/identity metadata only. Dealer assignments are not embedded as Security-owned fields.

### 24.3 Status change — TARGET

```text
PATCH /security/v1/users/{userId}/status
```

The final authorization policy must distinguish:

- ordinary approval/rejection administration;
- suspension;
- self-delete request;
- Executive/TenantAdmin/ModuleAdmin delete request.

### 24.4 Hard delete — TARGET

```text
DELETE /security/v1/platform/users/{userId}
```

SuperAdmin checker only, subject to the confirmed deletion preconditions.

---

## 25. Role and Group APIs

### 25.1 Global role catalogue — TARGET

```text
GET /security/v1/roles
```

Phase-1 catalogue is fixed to approved classifications rather than allowing each Tenant to create business role identities.

### 25.2 Set/replace operating role — TARGET

```text
PUT /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

Conceptual request:

```json
{
  "role": "PC"
}
```

Valid values are the approved operating classifications.

This API:

- replaces the prior active operating role for that USER/Tenant;
- rejects admin/operating persona conflicts;
- enforces one PM per Tenant;
- updates the role-aligned Group membership;
- records Security audit evidence.

### 25.3 Remove operating role — TARGET

```text
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

Removal changes Tenant authorization only; it does not delete the global USER. The USER also leaves the corresponding role-aligned Group.

### 25.4 Role-aligned Groups — TARGET

The Phase-1 Groups are system-defined operating-role views/collections.

Logical APIs:

```text
GET /security/v1/tenants/{tenantId}/groups
GET /security/v1/tenants/{tenantId}/groups/{roleKey}
GET /security/v1/tenants/{tenantId}/groups/{roleKey}/users
```

These APIs expose the users currently assigned to each operating role Group.

No independent Group-permission API is required because Group permissions are the role's Tenant bundle.

No separate Group membership write is required to grant operating authorization; the operating-role assignment API is authoritative and updates Group membership automatically.

### 25.5 Administrative-role assignment — TARGET SEMANTICS, EXACT CONTRACT OPEN

Administrative roles require additive/removal semantics because admin roles may coexist.

The target API must support assigning/removing `ModuleAdmin` and `TenantAdmin` with their approved scopes while enforcing global exclusion from operating roles.

Exact URI/body for admin-role scope should be finalized together with the detailed admin-permission design.

### 25.6 SuperAdmin assignment — DEFERRED

Initial/subsequent SuperAdmin creation and assignment is outside this document except for the confirmed responsibilities explicitly stated in this design.

---

## 26. Permission-configuration APIs

### 26.1 Module and permission discovery — CONFIRMED / EXISTING CAPABILITY TO RETAIN

Security must expose the registered module catalogue and the permissions available within each module.

Target logical APIs:

```text
GET /security/v1/platform/modules
GET /security/v1/platform/modules/{moduleKey}
GET /security/v1/platform/modules/{moduleKey}/permissions
```

The current module catalogue response may already contain permission details. The explicit `/permissions` resource is included in the target contract because the administration flow requires a clear API that answers, "Which permissions are currently available in this module?"

Module catalogue registration/update remains conceptually equivalent to:

```text
PUT /security/v1/platform/modules/{moduleKey}/catalog
```

### 26.2 Platform default role bundles — TARGET

Security must expose the platform default permission mapping for roles that have an approved default.

Logical API:

```text
GET /security/v1/platform/role-defaults/{roleKey}
```

Phase 1 seeds the approved `PC/TL/PM/CRM` defaults from Section 21.6 into a newly initialized Tenant.

This design does not invent defaults for Executive or TestUser.

### 26.3 Tenant role bundle — TARGET

Replace Tenant role creation with Tenant configuration of the permission bundle for a global role classification.

Conceptual APIs:

```text
GET /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
PUT /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
```

The PUT replaces the approved permission set for that role/Tenant atomically after validating that every permission exists and is active in an approved module catalogue.

The API does not create a new role identity.

The confirmed administration flow is:

```text
Tenant role bundle already seeded from approved default
      |
      v
SuperAdmin reviews current bundle
      |
      +-- acceptable -> role assignment
      |
      +-- change required
              |
              v
       GET module permissions
              |
              v
       PUT Tenant role bundle
              |
              v
       Security validates permission catalogue references
              |
              v
       role assignment
```

### 26.4 Role-aligned Groups — PHASE 1

Groups are included in Phase 1 because their target semantics are deliberately simple:

```text
Group == collection of users having one operating role in one Tenant
```

The Group does not independently grant permissions.

```text
Group role_key -> Tenant role permission bundle
```

This avoids the conflict in the current implementation where Group-derived roles are additive and permission sets are unioned.

Phase 1 therefore retains the useful Group/listing concept but **does not retain** current arbitrary Group-to-role inheritance as an authorization mechanism.

Custom/general-purpose Groups may be considered later if required.

---

## 27. Web BFF orchestration APIs

These are logical frontend contracts implemented within the Web module, not Security-owned persistence APIs and not a separate BFF module.

Examples:

### 27.1 User approval view

```text
GET /bff/admin/users?status=PENDING
```

Web BFF obtains Security data and returns a UI-appropriate representation.

### 27.2 User role + Dealer assignment

Conceptually:

```text
PUT /bff/admin/tenants/{tenantId}/users/{userId}/assignment
```

Possible UI request:

```json
{
  "operatingRole": "PC",
  "dealerIds": ["D1"]
}
```

Web BFF orchestrates Security + Audit Core but stores neither record.

The actual Dealer cardinality is not constrained in Phase 1.

The corresponding Security role-aligned Group membership is updated automatically by the role assignment; the Web BFF does not need a second Group-membership write.

### 27.3 Partial-failure behaviour

The Web BFF must report partial failure accurately and must not fabricate a combined success.

Backends remain fail-safe because Security functional role alone does not satisfy Audit Core Dealer/business-scope checks.

---

## 28. Security audit trail

### 28.1 Required authoritative events — CONFIRMED

Security records authoritative audit evidence for at least:

- onboarding request;
- Clerk identity binding;
- USER approval;
- USER rejection;
- USER activation;
- suspension;
- deletion request / transition to DISABLED;
- SuperAdmin hard delete;
- operating-role assignment/change/removal;
- resulting role-aligned Group membership change;
- administrative-role assignment/change/removal;
- Tenant role-bundle permission changes;
- module permission-catalogue changes;
- Tenant authorization changes;
- important authentication/lifecycle synchronization failures.

### 28.2 Event fields

At minimum where applicable:

- event/change ID;
- correlation ID;
- actor USER/service;
- target USER/resource;
- Tenant/module scope;
- operation;
- old/new state or safe change summary;
- outcome;
- UTC timestamp;
- reason where supplied.

Never store credentials, Clerk session JWTs, passwords, OTP values or secrets in audit records.

### 28.3 Hard-delete audit

Hard deletion must leave enough non-credential audit evidence to prove:

- who requested deletion;
- when the USER was disabled;
- who executed final hard deletion;
- when final deletion occurred;
- outcome/correlation identifiers.

The audit record must not depend on the deleted live USER row continuing to exist.

---

## 29. Session/status enforcement

### 29.1 Every authorization request checks live USER status — CONFIRMED

Because Security is called synchronously for each protected request, status changes take effect on the next authorization decision without waiting for a Verigence-issued token to expire.

### 29.2 Role and permission changes — CONFIRMED TARGET EFFECT

Because permissions are resolved by Security at authorization time, changing a USER's role or a Tenant role bundle affects subsequent protected requests without reissuing a Verigence user token.

Role-aligned Group membership follows the role assignment and has no independent authorization cache.

### 29.3 Clerk session still valid after Security suspension

Even if a Clerk session JWT remains cryptographically valid, Security denies the USER because status is no longer ACTIVE.

Clerk lifecycle termination/ban remains defense in depth.

---

## 30. Audit Core integration

### 30.1 Human authentication contract — TARGET

Audit Core must migrate away from trusting Security-issued human JWTs.

Target human request contract:

```text
Client/Web BFF -> Audit Core: Clerk session JWT
Audit Core: validate Clerk JWT locally
Audit Core -> Security: synchronous authorization decision
Audit Core: evaluate Dealer/business scope locally
```

### 30.2 Functional authorization authority — RETAIN

Security remains the sole functional authorization authority.

### 30.3 Business scope authority — RETAIN

Audit Core remains the Dealer/Outlet/business-scope authority.

### 30.4 Default operational permission bundles — EXISTING AND RETAIN AS SECURITY DEFAULT SOURCE

Audit Core already contains an approved `PC/TL/PM/CRM` default cross-module bundle covering Audit Core and DI permissions. Security uses those approved values as the Phase-1 platform defaults listed in Section 21.6.

This does not transfer permission ownership to Audit Core; Audit Core owns its permission catalogue while Security owns the default/Tenant role mapping used for authorization.

### 30.5 Existing Audit Core design conflict

Current Audit Core design states that it verifies Security-issued JWTs through Security JWKS and authorizes from `permissions[]` claims.

That human-token assumption conflicts with this target and will require a later Audit Core design update after this Security design is approved.

No Audit Core file is changed by this Security design work.

---

## 31. DI and service-to-service boundary

### 31.1 Direct human DI access — CONFIRMED

Human users may call DI directly for approved DI capabilities.

DI does **not** perform human onboarding, role assignment or USER lifecycle management.

For direct protected human access:

```text
Human -> DI with Clerk session JWT
DI validates Clerk JWT locally
DI -> Security authorization/check
Security evaluates ACTIVE USER + Tenant/role/permission
DI executes only after ALLOW
```

The human Clerk JWT is authentication evidence; DI does not derive Verigence permission merely from the existence of a valid Clerk session.

### 31.2 Audit Core -> DI — TARGET

Audit Core may also call DI internally using a dedicated machine/service identity.

The existing Security/DI architecture already contains Security-issued machine identities/tokens and DI validation of Security JWT/JWKS for `SYSTEM` / `SERVICE_INTEGRATION` actors. That capability is distinct from the human-token design and can be retained for Phase-1 service-to-service authentication, subject to audience/permission review.

Minimum internal target flow:

```text
Human -> Audit Core (Clerk JWT + Security authorization)
Audit Core -> DI (Audit Core service identity)
```

DI authorizes the Audit Core service identity only for the DI capabilities Audit Core requires.

### 31.3 Human provenance

When a human-triggered Audit Core action causes a DI call, Audit Core retains the initiating global USER identity in its authoritative audit/business history and may pass safe provenance context to DI when needed.

DI must accept such human context only from an authenticated trusted service caller; it must not treat an arbitrary user-supplied header as identity.

### 31.4 Delegated token exchange — DEFERRED

No sophisticated user-on-behalf-of token exchange is required in Phase 1.

### 31.5 Existing DI design conflict

Current DI Security-alignment design expects Security-issued USER JWTs for human authorization.

The target human DI contract is instead Clerk session JWT authentication plus synchronous Security authorization. The machine/service portion of the existing DI contract may remain useful.

No DI file is changed by this Security design work.

---

## 32. Failure handling and fail-closed rules

### 32.1 Clerk JWT invalid

Backend denies authentication before business processing.

### 32.2 Clerk JWT valid but no Verigence USER mapping

Security authorization denies.

### 32.3 USER not ACTIVE

Security authorization denies.

### 32.4 Tenant not ACTIVE / no Tenant role

Tenant-scoped authorization denies.

### 32.5 Permission absent from current Tenant role bundle

Security authorization denies.

### 32.6 Security unavailable

Protected business request fails closed. Phase 1 does not use stale local authorization as an allow fallback.

### 32.7 Audit Core Dealer association absent

Audit Core denies Dealer-scoped business action even if Security functional permission is allowed.

### 32.8 Role assignment conflicts

Security rejects:

- second active operating role for same USER/Tenant;
- second active PM in same Tenant;
- admin role assigned to a USER with any active operating persona;
- operating role assigned to a USER with any administrative persona.

The role-aligned Group representation cannot bypass these checks because Group membership is derived from the operating-role assignment.

### 32.9 Hard-delete dependency failure

If final deletion cannot complete safely across required live identity stores, Security must record failure and avoid reporting hard-delete success.

Exact compensation/retry ordering with Clerk is finalized in implementation design after retention/deletion policy approval.

---

## 33. Target conceptual data model

This is a conceptual target. Physical DDL is not authorized by this document.

### 33.1 Core identity

```text
security.users
  user_id
  display/profile fields required by approved USER model
  email / normalized unique identity fields as approved
  status: PENDING | REJECTED | ACTIVE | SUSPENDED | DISABLED
  created_at_utc
  updated_at_utc
```

```text
security.external_identities
  external_identity_id
  user_id
  provider = CLERK
  provider_subject
  status
  bound_at_utc
```

### 33.2 Onboarding

```text
security.platform_user_onboarding_settings
security.platform_user_onboarding_requests
```

Retain the global-not-Tenant onboarding concept.

### 33.3 Role definitions

```text
security.role_definitions
  role_key
  role_class: OPERATING | ADMIN | TEST
  display_name
  status
```

Phase-1 fixed keys include:

- PC
- TL
- PM
- CRM
- Executive
- ModuleAdmin
- TenantAdmin
- SuperAdmin
- TestUser

### 33.4 Platform default role permissions

```text
security.platform_role_permission_defaults
  role_key
  permission_key
  source_catalog_version
  status
```

Phase-1 approved seed exists for:

- PC
- TL
- PM
- CRM

Executive and TestUser remain pending explicit default approval.

### 33.5 Operating role assignment

```text
security.user_tenant_operating_roles
  assignment_id
  user_id
  tenant_id
  role_key
  status
  valid_from_utc
  valid_to_utc
  assigned_by_user_id
  assigned_at_utc
```

Required constraints:

```text
one ACTIVE row per (user_id, tenant_id)
one ACTIVE PM per tenant_id
role_key must be OPERATING
```

### 33.6 Role-aligned Groups

Phase-1 operating Groups may be implemented as a derived/query view over `user_tenant_operating_roles` or as persisted group metadata whose membership is transactionally synchronized from the operating-role assignment.

The authoritative semantic relationship is fixed:

```text
Tenant + role_key -> one role-aligned Group
Group membership  -> users whose active operating role is role_key
Group permissions -> same Tenant role bundle for role_key
```

There is no independent Group permission grant.

The physical choice between a derived view and persisted metadata is an implementation detail to settle in the physical DB design; it must preserve the same semantics.

### 33.7 Administrative role assignment

Conceptually:

```text
security.user_admin_role_assignments
  assignment_id
  user_id
  role_key
  scope_type
  scope_id
  status
  assigned_by_user_id
  assigned_at_utc
```

Exact SuperAdmin/ModuleAdmin/TenantAdmin scope rules require final admin-role design.

### 33.8 TestUser assignment

A dedicated assignment representation may be used if TestUser is Tenant-contextual. Exact assignment scope is finalized with the TestUser permission bundle.

### 33.9 Module permissions — EXISTING CONCEPT RETAINED

```text
security.modules
security.permissions
security.module_role_templates
security.module_role_template_permissions
```

### 33.10 Tenant role permission bundle

```text
security.tenant_role_permissions
  tenant_id
  role_key
  permission_key
  assigned_by_user_id
  assigned_at_utc
```

This replaces Tenant-created business role identity with Tenant-specific permission configuration for a global role classification.

### 33.11 Deletion requests

```text
security.user_deletion_requests
  deletion_request_id
  user_id
  requested_by_user_id
  requested_at_utc
  reason
  status
  checked_by_user_id
  checked_at_utc
  outcome
```

This preserves maker/checker evidence separately from the live USER status.

### 33.12 Security audit

Retain/extend the existing immutable administrative/security event/change-record concept so it can survive live USER hard deletion without cascade loss.

### 33.13 Objects not used as Phase-1 authorization gates

- `tenant_memberships`
- current arbitrary Group-to-role additive grants
- current Group-derived permission union
- Security-issued human access sessions/tokens
- per-user human token authorization versions for token invalidation

Existing Group data/API implementation may be reused only after it is constrained to the role-aligned Group semantics above; the current arbitrary additive RBAC behaviour is not retained.

Historical tables need not be destructively dropped merely because they leave the active runtime model.

---

## 34. Target API contract summary

Exact OpenAPI definitions follow design approval. Target semantic surface:

### Authentication / onboarding

```text
POST /security/v1/onboarding/users                    # global onboarding gate/request
POST /security/v1/onboarding/users/{id}/bind          # bind authenticated Clerk identity if retained in final UI flow
POST /security/v1/auth/precheck                       # optional existing UX gate
```

Human credential entry/sign-in itself is Clerk-owned rather than a Security-issued-token login API.

### USER administration

```text
GET    /security/v1/platform/users
GET    /security/v1/platform/users/{userId}
PATCH  /security/v1/users/{userId}/status
DELETE /security/v1/platform/users/{userId}
```

### Operating-role administration

```text
PUT    /security/v1/tenants/{tenantId}/users/{userId}/operating-role
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

### Role-aligned Groups

```text
GET /security/v1/tenants/{tenantId}/groups
GET /security/v1/tenants/{tenantId}/groups/{roleKey}
GET /security/v1/tenants/{tenantId}/groups/{roleKey}/users
```

### Platform default role bundles

```text
GET /security/v1/platform/role-defaults/{roleKey}
```

### Tenant role-bundle administration

```text
GET /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
PUT /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
```

### Runtime authorization

```text
POST /security/v1/authorization/check
```

### Module / permission catalogue

```text
GET /security/v1/platform/modules
GET /security/v1/platform/modules/{moduleKey}
GET /security/v1/platform/modules/{moduleKey}/permissions
PUT /security/v1/platform/modules/{moduleKey}/catalog
```

### Tenant administration

Existing Tenant entity/lifecycle APIs remain valuable. Detailed authority mapping to the redesigned admin roles, especially SuperAdmin, is finalized with the admin-role design rather than inferred here.

---

## 35. Current -> Target gap analysis

| Area | Current `dev` | Target | Classification |
|---|---|---|---|
| Global USER | v1.4.2 global USER/onboarding exists. | One global USER, no per-Tenant re-onboarding. | **EXISTING AND RETAIN** |
| Clerk external identity mapping | Exists. | Clerk subject maps to one global USER. | **EXISTING AND RETAIN** |
| Global onboarding gate | Platform-global onboarding key exists. | Global gate remains; no Tenant/role/Dealer during onboarding. | **EXISTING AND RETAIN** |
| Credential handling in Security | Current onboarding/login APIs accept password/TOTP/OTP and broker Clerk Backend APIs. | First-party Clerk authentication/session flow; Security does not own human credential flow. | **EXISTING BUT MODIFY** |
| MFA | Current code/design includes TOTP/MFA concepts. | No Phase-1 MFA requirement. | **DEFERRED** |
| USER statuses | Current status surface includes ACTIVE/SUSPENDED/DISABLED/EXITED; PENDING exists in onboarding. | PENDING/REJECTED/ACTIVE/SUSPENDED/DISABLED; hard DELETE separate. | **EXISTING BUT MODIFY** |
| REJECTED lifecycle | Not part of current global status request. | Required. | **NEW/MODIFY** |
| Hard USER deletion | No confirmed target maker/checker global hard-delete API in current global USER surface. | DISABLED maker state + SuperAdmin DELETE checker. | **NEW/MODIFY** |
| Tenant membership | Historical/current tables remain, some legacy code still references them. v1.4.2 says no runtime membership prerequisite. | No membership authorization gate. | **RETIRE FROM RUNTIME** |
| Role definition | Current `security.roles` are Tenant-owned rows. | Global fixed role classifications. | **EXISTING BUT MODIFY** |
| Tenant role creation API | Current `/admin/tenants/{tenantId}/roles` creates arbitrary Tenant roles. | Tenant configures permission bundle for approved global role keys. | **RETIRE/REPLACE** |
| Operating-role cardinality | Current assignment API is additive by role ID. | Exactly one active operating role per USER/Tenant. | **EXISTING BUT MODIFY** |
| One PM per Tenant | Not enforced by generic current RBAC. | Required invariant. | **NEW** |
| Direct role union | Current effective permission resolver unions multiple direct Tenant roles. | One operating role per USER/Tenant. | **RETIRE FOR OPERATING USERS** |
| Groups | Current implementation has arbitrary Group CRUD, memberships and Group-to-role assignment; effective permissions union Group-derived roles. | Phase-1 Groups are role-aligned collections for PC/TL/PM/CRM/Executive and inherit exactly the same Tenant role bundle; no separate Group permission grant. | **EXISTING BUT SIMPLIFY/MODIFY** |
| Platform default operational bundles | Approved Audit Core baseline already defines PC/TL/PM/CRM cross-module defaults, but current target Security design did not previously freeze them as the onboarding seed. | Security seeds those exact Audit Core + DI defaults into each new Tenant. | **EXISTING DESIGN INPUT / ADD TO TARGET** |
| Executive default bundle | Executive exists, but current approved cross-module default bundle explicitly covers PC/TL/PM/CRM only. | Executive role/group retained; exact default permission seed requires explicit approval. | **OPEN** |
| Platform/admin roles | Current platform roles exist. | Admin personas retained conceptually but exact bundles/scopes redesigned. | **EXISTING BUT MODIFY** |
| SuperAdmin | Existing migration grants `platform.super_admin` every active permission and bootstrap code exists. | Confirmed responsibilities include hard-delete checker and Tenant role-bundle permission management; broader authority/bootstrap deferred. | **EXISTING BUT MODIFY / DEFER** |
| Module permission catalogue | Existing module catalogue, permissions and role templates. | Modules publish permissions; Security exposes module permission discovery; Security remains registry/authority. | **EXISTING AND RETAIN / EXTEND CONTRACT** |
| Role templates | Current templates seed Tenant role objects. | Approved templates/defaults seed Tenant permission bundles for global role classifications. | **EXISTING BUT MODIFY** |
| Tenant role permissions | Current permissions bind to Tenant role IDs. | Bind Tenant + global role_key + permission_key. | **EXISTING BUT MODIFY** |
| Human runtime token | Current `/auth/login` and access session flows issue Verigence access tokens. | Clerk session JWT only for human authentication. | **RETIRE HUMAN TOKEN ISSUANCE** |
| Security JWKS for human USER token | Current downstream modules trust Security JWT/JWKS. | Not used for human Phase-1 access. | **RETIRE FOR HUMAN FLOW** |
| Security JWKS/service token | Existing machine/SYSTEM/SERVICE_INTEGRATION token model. | May remain for approved S2S use. | **EXISTING AND RETAIN/MODIFY** |
| Authorization version | Current `user_tenant_authorization_state` supports token invalidation. | Not required for Phase-1 human-token authorization because Security is called live. Can remain for compatibility/future use. | **DEFER FROM ACTIVE HUMAN DESIGN** |
| Runtime authorization | Current modules receive permissions embedded in Security JWT. | Protected resource server validates Clerk JWT and calls Security synchronously for required permission. | **REDESIGN** |
| Security authorization API | Internal gate logic exists, but not the target Clerk-JWT PDP contract. | Add explicit synchronous authorization-check contract. | **NEW/MODIFY** |
| Dealer/Outlet in Security | Audit Core design already separates business scope. | Security stores no Dealer assignment. | **RETAIN BOUNDARY** |
| Web BFF | No consolidated Web BFF boundary in current Security runtime. | BFF capability is part of Web module; no separate BFF module. | **NEW DESIGN BOUNDARY** |
| Audit Core human trust | Current design expects Security-issued JWT + permissions. | Clerk JWT + Security synchronous AuthZ + Audit Core business scope. | **DEPENDENT DESIGN CHANGE** |
| DI human trust | Current DI expects Security-issued USER JWT. | Human may call DI directly using Clerk JWT authentication + synchronous Security authorization; DI performs no onboarding. | **DEPENDENT DESIGN CHANGE** |
| DI service trust | DI already supports Security service/system identities. | Reuse for Audit Core -> DI where appropriate. | **EXISTING AND RETAIN/MODIFY** |
| Security audit records | Existing admin/security change/audit structures exist. | Extend to redesigned lifecycle, hard delete, role defaults and role-aligned Groups. | **EXISTING AND RETAIN/MODIFY** |

---

## 36. Migration strategy

No migration is executed by this design document.

After approval, migration should be additive and auditable rather than rewriting historical migrations.

Recommended sequence:

1. freeze this design and the target API/data contracts;
2. introduce new target role-definition and assignment structures;
3. add REJECTED/deletion-request lifecycle structures;
4. add the new authorization-check service contract;
5. move first-party human authentication to Clerk session JWT validation;
6. migrate active operating-role assignments into one-role-per-USER/Tenant representation after conflict analysis;
7. load the approved PC/TL/PM/CRM platform default bundles from the current approved Audit Core cross-module baseline;
8. seed Tenant-specific permission bundles from those approved defaults;
9. simplify Groups to role-aligned collections and remove current additive Group-derived permission behaviour from Phase-1 authorization;
10. retire human Security token issuance routes after all clients/modules are migrated;
11. keep historical tables/routes disabled or compatibility-only until explicit retention cleanup is approved;
12. align Audit Core and DI designs/contracts after Security behaviour is proven.

### Migration safety checks

Before migrating active role assignments, identify:

- users currently holding multiple direct roles in one Tenant;
- users receiving additional effective roles through existing arbitrary Groups;
- users mixing current platform/admin and Tenant roles;
- Tenants with more than one user who would map to PM;
- permissions currently granted by arbitrary custom Tenant roles that have no mapping to the approved target role catalogue;
- current Group memberships that do not correspond 1:1 with the USER's target operating role.

These require explicit remediation rather than automatic guessing.

---

## 37. Phase-1 implementation sequence after design approval

1. **Approve target Security design and open decisions required for coding.**
2. **Produce target Security API/OpenAPI and physical DB design.**
3. **Implement Clerk session JWT verification for human requests.**
4. **Implement/align global USER onboarding and PENDING/REJECTED/ACTIVE lifecycle.**
5. **Implement status change + DISABLED deletion-request flow + SuperAdmin hard-delete checker API.**
6. **Implement global role definitions and one operating-role-per-USER/Tenant assignment model.**
7. **Implement Phase-1 role-aligned Groups as the PC/TL/PM/CRM/Executive user collections tied 1:1 to operating roles.**
8. **Enforce one PM per Tenant and admin/operating exclusivity.**
9. **Expose module permission discovery.**
10. **Seed the approved PC/TL/PM/CRM Audit Core + DI platform default permission bundles into Tenant role bundles.**
11. **Implement SuperAdmin Tenant role-bundle review/update flow.**
12. **Implement synchronous Security authorization-check API and use common in-process logic for Security admin endpoints.**
13. **Implement Web BFF user-administration flows inside the Web module without moving authority into Web.**
14. **Implement/align Audit Core Dealer assignment APIs for PC/TL/PM/CRM associations without Phase-2 cardinality rules.**
15. **Migrate Audit Core human auth contract to Clerk JWT + synchronous Security AuthZ.**
16. **Align DI direct-human protected access to Clerk JWT + synchronous Security AuthZ; DI remains outside onboarding.**
17. **Retain the required machine/service auth path for Audit Core -> DI.**
18. **Retire Security-issued human access-token flows and downstream USER-JWT assumptions.**
19. **Run migration reconciliation and end-to-end authorization/lifecycle tests before production use.**

---

## 38. Deferred Phase-2 items

The following are deliberately not implemented or overdesigned in Phase 1:

- MFA;
- Dealer staffing/cardinality rules;
- number of Dealers supported by each PC/TL/PM/CRM;
- exact Dealer coverage ratios;
- user-to-Outlet restrictions unless separately approved;
- distributed authorization projections;
- Verigence-issued human JWT;
- custom human OAuth authorization-server implementation;
- authorization permission-epoch/revocation cache design for a Verigence human token;
- delegated user-on-behalf-of token exchange;
- arbitrary/custom Groups and Group-specific permission inheritance beyond the Phase-1 role-aligned Groups;
- detailed SuperAdmin powers/bootstrap beyond the responsibilities explicitly confirmed in this document;
- performance caching of Security allow decisions until measurement proves it necessary.

---

## 39. Open decisions

The following must be resolved before the relevant implementation area is finalized:

1. **SuperAdmin design:** bootstrap/initial SuperAdmin creation, broader powers, subsequent SuperAdmin assignment and Tenant-administration authority beyond the currently confirmed responsibilities.
2. **Global deletion request scope:** whether/how Executive or TenantAdmin may request deletion of a global USER who is authorized in other Tenants.
3. **Maker/checker actor separation:** whether checker must always be a different human from maker in every edge case.
4. **Reactivation:** allowed transitions from SUSPENDED, REJECTED and DISABLED.
5. **TestUser:** exact permission bundle, Tenant assignment scope and final coexistence rule.
6. **Administrative scope:** exact ModuleAdmin and TenantAdmin scope model and permission bundles.
7. **Outlet assignment:** whether Phase 1 needs any USER-to-Outlet business restriction in Audit Core beyond Dealer association.
8. **Hard-delete retention:** exact non-PII actor tombstone/snapshot and retention period across Security/Audit records.
9. **Internal caller authentication to Security AuthZ:** exact machine credential profile to use for Web BFF/backend-to-Security calls, reusing approved service identity capability rather than inventing a human-token scheme.
10. **Executive default permission bundle:** exact Audit Core + DI default permission seed for Executive.

---

## 40. Supersession and alignment rule

After approval, this document is intended to become the Security architecture authority for the topics it covers.

Where existing Security documents/code conflict with this target, the conflict must be resolved through explicit implementation work; historical documents and migrations are not silently rewritten.

Known dependent conflicts requiring later alignment include:

- Audit Core's current assumption that human authorization arrives in a Security-issued JWT containing `permissions[]`;
- DI's current assumption that Security-issued USER JWTs are the canonical human authorization contract;
- Security's current human login/token issuance flow;
- Tenant-owned role objects and additive/group-derived effective-role resolution.

No Audit Core or DI file is modified as part of this design document.

---

## 41. Final Phase-1 security invariant

```text
HUMAN IDENTITY
  Clerk authenticates
       |
       v
  Clerk session JWT
       |
       v
PROTECTED RESOURCE SERVER
  Security / Audit Core / DI as applicable
  validate Clerk JWT locally
       |
       v
SECURITY AUTHORIZATION
  Clerk subject -> global USER
  USER must be ACTIVE
  Tenant context where applicable
  exactly one operating role per USER/Tenant
  role-aligned Group = same operating role collection
  Tenant role bundle seeded from approved default and optionally customized
  required permission must be present
       |
       v
ALLOW / DENY
       |
       +--> Audit Core additionally checks Dealer/business scope where applicable
```

The governing separation is:

> **Clerk proves who the human is. Security decides what that global Verigence USER is functionally allowed to do. Role-aligned Groups are the Tenant user collections for the same operating roles and never form a second permission authority. Security starts from approved default role bundles and allows Tenant-specific SuperAdmin changes. Audit Core decides Dealer/business scope for Audit operations. DI may serve authorized humans directly for approved DI capabilities but owns no human onboarding. The Web BFF is part of the Web module and owns no Security authority.**