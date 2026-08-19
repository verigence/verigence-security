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
- Clerk-based human authentication through Security only;
- the Phase-1 human token model;
- USER onboarding and approval;
- USER lifecycle, suspension and hard deletion;
- USER role classifications and assignment rules;
- administrative-role rules;
- the single Phase-1 `SuperAdmin`;
- `TestUser` and `TestTenant`;
- role-aligned operating Groups;
- module permission catalogues;
- platform default and Tenant-specific role-to-permission mapping;
- synchronous runtime authorization;
- `ServiceIntegration` machine identity and module-to-module authentication;
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
- Dealer/Outlet business assignment.

One person has one global Verigence USER identity. The same USER may later receive authorization in zero, one or multiple Tenants without creating another Verigence USER or Clerk account.

### 2.2 Authentication — CONFIRMED

Clerk owns human credential storage and credential verification. **Verigence Security is the only Verigence module that integrates with Clerk.**

Phase 1:

- Web/Mobile does **not** call Clerk directly;
- Web/Mobile does **not** include a Clerk SDK or Clerk publishable/secret key;
- Audit Core, DI and the Web BFF do **not** call Clerk or validate Clerk session tokens;
- human signup, email verification and login requests reach Security through Verigence APIs;
- Security calls the Clerk Backend API for human user creation and credential/email verification;
- the canonical human login request requires only `identifier` and `password`; `tenantId` is not part of login because login establishes the global USER identity rather than a Tenant authorization context;
- the canonical employee signup request captures `firstName`, `lastName`, email, mobile number and password, while the user-facing **Verigence Identifier** is carried through the existing platform-global onboarding-key contract (`X-Onboarding-Key`);
- a client may send optional Device ID and Geo request-context headers on signup/login, but Phase 1 does not require them, persist them, bind them to onboarding/login, or use them as authentication/authorization gates;
- Phase 1 does not require TOTP/MFA as part of the canonical login contract;
- passwords, email OTP values and future authentication secrets are transient request secrets and are never persisted, audited, traced, cached or logged by Verigence;
- after successful Clerk-backed authentication, Security resolves the Clerk subject to the global Verigence USER and issues the Verigence human access token/session used by Verigence clients and resource servers;
- Security does not make Clerk authoritative for Verigence roles or permissions.

Security also issues short-lived JWTs for registered **machine/service identities** under the `ServiceIntegration` model defined in this document. Machine tokens are a separate actor/token model from the Security-issued human access token.

### 2.3 Human authorization — CONFIRMED

Verigence Security is the sole source of truth for functional authorization.

For Phase 1, every protected backend business request requiring Verigence human authorization uses Security's authorization service.

The Security-issued human access JWT proves the authenticated Verigence USER identity at the resource server. It is **not** the authorization database: authoritative roles and permissions remain in Security and are evaluated synchronously.

Phase 1 therefore has:

- one Verigence human authentication facade in Security backed by Clerk Backend APIs;
- no direct Clerk trust boundary in Web/Mobile, Audit Core or DI;
- no authoritative human permission claims copied into the human JWT as a substitute for live Security authorization;
- no distributed Security authorization projection in Audit Core/DI;
- no authorization event replication for normal runtime authorization;
- no opaque-token introspection design;
- live Security USER status and authorization checked synchronously for protected operations.

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

Current human administrative classifications are:

- `ModuleAdmin`
- `TenantAdmin`
- `SuperAdmin`

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

Phase-1 scope semantics are:

```text
SuperAdmin          = one platform-wide human administrator with all ACTIVE permissions
TenantAdmin(T1)     = administration of Tenant T1 across modules
ModuleAdmin(AUDIT)  = administration of Audit Core across Tenants
ModuleAdmin(DI)     = administration of DI across Tenants
```

### 2.6 SuperAdmin — CONFIRMED

Phase 1 has **exactly one active SuperAdmin**.

The SuperAdmin Clerk identity has already been created. The Clerk subject supplied for this design is:

```text
user_3I7F…jH9hBMxpN
```

The value above is recorded exactly as supplied in the design discussion. If the ellipsis is a redaction, implementation requires the complete exact Clerk subject before the identity can be bound.

Phase-1 SuperAdmin receives **all ACTIVE permissions across all registered Verigence modules**, including Security, Audit Core and DI. When a new module permission becomes ACTIVE in Security's registered catalogue, SuperAdmin receives that permission by default. SuperAdmin therefore does not require a manually maintained Tenant role bundle.

Confirmed SuperAdmin responsibilities include:

- platform-wide administration;
- Tenant creation and Tenant lifecycle administration;
- module/permission catalogue visibility and administration according to registered capabilities;
- Tenant role-bundle review and update;
- administration of users and administrative assignments;
- all registered functional permissions across modules;
- all registered administrative permissions across modules;
- final hard deletion of a global USER;
- reactivation of non-active employee USERs as defined in Section 10.

No second active SuperAdmin is allowed in Phase 1. Creation/assignment of additional SuperAdmins is therefore outside the Phase-1 design.

### 2.7 TestUser and TestTenant — CONFIRMED

A dedicated `TestUser` classification is required in Phase 1.

The TestUser Clerk identity has already been created. The Clerk subject supplied for this design is:

```text
user_3I7H…eXFRoeoud
```

The value above is recorded exactly as supplied in the design discussion. If the ellipsis is a redaction, implementation requires the complete exact Clerk subject.

A dedicated `TestTenant` is also required in Phase 1.

Rules:

- `TestTenant` has one canonical Tenant identity originating from Security;
- the same canonical Tenant ID must be represented/recognized in Security, Audit Core and DI;
- modules must not create unrelated TestTenant identifiers for the same test environment;
- `TestUser` is assigned to `TestTenant`;
- `TestUser` receives the same functional privileges as `PC` for `TestTenant`;
- the TestUser permission mapping therefore follows the `TestTenant` PC permission bundle rather than maintaining an independent divergent permission list;
- `TestUser` remains a distinct test classification and is not an employee operating-role assignment for production Tenants.

### 2.8 Dealer/Outlet assignment — CONFIRMED

Dealer/Outlet assignment is not Security RBAC.

For Phase 1, **Dealer and Outlet are the same business-scope concept for implementation purposes**. There is no separate Outlet assignment layer in Phase 1.

Dealer/Outlet assignment belongs to Audit Core and remains independent of:

- global USER identity;
- role definition;
- role-to-permission mapping.

The business model expects Dealer/Outlet entities to have relevant `PC`, `TL`, `PM` and `CRM` users associated with them.

Phase 1 must **not** enforce staffing/cardinality rules such as:

- how many Dealer/Outlets one PC covers;
- how many Dealer/Outlets one TL covers;
- how many Dealer/Outlets one PM covers;
- how many Dealer/Outlets one CRM covers;
- how many users of each role a Dealer/Outlet requires.

Those rules are deferred.

`Executive` is Tenant-wide and does not require Dealer/Outlet assignment.

### 2.9 USER lifecycle — CONFIRMED

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
- only SuperAdmin may execute the final hard delete;
- Phase 1 permits the same human to be maker and checker when that human is the SuperAdmin;
- USER deletion is global and independent of Tenant context in Phase 1.

Reactivation from a non-active employee state back to `ACTIVE` is a SuperAdmin-only action in Phase 1.

### 2.10 Web BFF/API layer — CONFIRMED

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
- Dealer/Outlet assignments;
- authorization decisions as source of truth;
- Clerk credentials, Clerk SDK/configuration or direct Clerk integration.

The exact Mobile access path is not changed by this observation and must not be inferred from the Web BFF decision.

### 2.11 ServiceIntegration — CONFIRMED

Phase 1 includes a machine-only `ServiceIntegration` classification for module-to-module authentication and authorization.

`ServiceIntegration`:

- is not a human USER role;
- is not authenticated by Clerk;
- cannot be assigned to PC/TL/PM/CRM/Executive/TestUser/TenantAdmin/ModuleAdmin/SuperAdmin human identities;
- uses machine credentials registered in Security;
- receives short-lived Security-issued machine JWTs;
- may access multiple modules, but each registered service principal is limited to its approved target audiences and integration permissions;
- does not automatically receive every module permission merely because it is classified as `ServiceIntegration`.

---

## 3. Target platform architecture

```text
                         HUMAN USER
                        /          \
                       /            \
              Web application      Mobile client
              + Web BFF/API             |
                    |                    |
                    +---------+----------+
                              |
                              | Verigence onboarding/login APIs
                              v
                        +-----------+
                        | SECURITY  |
                        |           |
                        | USER SoT  |
                        | AuthN     |
                        | AuthZ SoT |
                        | roles     |
                        | perms     |
                        +-----+-----+
                              |
                              | Clerk Backend API only
                              v
                           +-------+
                           | Clerk |
                           +-------+

After successful login Security issues the Verigence human access JWT.
That token is presented to Security / Audit Core / DI as applicable.
Protected Audit Core / DI operations still obtain a synchronous
Security authorization decision using their ServiceIntegration identity.
```

Human access to DI is allowed when DI exposes a human-facing protected capability. DI remains outside human onboarding and has no Clerk integration.

### 3.1 Core ownership rule

```text
Clerk              = store/verify human credentials behind the Security-only backend integration
Security           = expose Verigence human signup/login, map Clerk identity to the global USER, issue human access JWTs and decide functional authorization
Security           = register machine identities and issue ServiceIntegration machine JWTs
Audit Core         = validate Security human JWTs, obtain Security functional authorization and decide Dealer/Outlet business scope
DI                 = validate Security human JWTs, obtain Security functional authorization and provide generic document intelligence; owns no human onboarding
Web BFF            = client-facing composition/orchestration inside the Web module only; no Clerk integration
ServiceIntegration = machine-only module-to-module identity/authorization classification
```

---

## 4. Trust boundaries

### 4.1 Clerk boundary — CONFIRMED

Clerk owns:

- human credential storage and verification;
- email/sign-up authentication functions provided by Clerk;
- Clerk account lifecycle functions used by Security.

Only Security may hold Clerk integration configuration/secrets and call Clerk Backend APIs.

Web/Mobile, Web BFF, Audit Core and DI must not:

- call Clerk Frontend or Backend APIs;
- include a Clerk SDK;
- hold Clerk publishable/secret keys;
- receive or persist Clerk session tokens as the Verigence human session model.

Verigence Security owns the mapping from Clerk subject to global Verigence USER and owns the Verigence-facing human authentication/session boundary.

Clerk Organizations, Clerk roles and Clerk custom permission claims must not become the Verigence authorization source of truth.

### 4.2 Security boundary — CONFIRMED

Security owns:

- the only Verigence-to-Clerk integration;
- global USER record and status;
- Clerk-to-Verigence identity mapping;
- Verigence human authentication endpoints and Security-issued human access tokens;
- Tenant entity and Tenant lifecycle capability;
- global role classifications;
- USER role assignments;
- role-aligned operating Groups;
- module permission catalogue registry;
- platform default and Tenant-specific operating-role permission bundles;
- functional authorization decisions;
- one Phase-1 SuperAdmin identity/authority mapping;
- machine/service client registry;
- ServiceIntegration audience/permission grants;
- machine-token issuance and signing/JWKS for ServiceIntegration;
- Security administrative audit history.

### 4.3 Audit Core boundary — CONFIRMED

Audit Core owns the Phase-1 Dealer/Outlet business scope and business assignment.

In Phase 1, Dealer and Outlet are the same business entity for assignment purposes; there is no separate Outlet-level user restriction model.

Security must not store Dealer/Outlet IDs merely to make authorization convenient.

For a Dealer/Outlet-scoped Audit operation:

```text
ALLOW = Security functional authorization
        AND
        Audit Core Dealer/Outlet business-scope authorization
```

SuperAdmin's all-permission rule concerns functional permissions. Audit Core business-scope rules remain a separate boundary unless Audit Core explicitly defines an administrative business-scope bypass later.

### 4.4 DI boundary — CONFIRMED

Human users **may call DI directly** for approved DI capabilities.

DI has no role in human onboarding or human role assignment and has no direct Clerk integration.

For a protected direct human DI request:

```text
Human -> DI with Security-issued human access JWT
DI validates Security JWT locally using Security trusted signing keys/JWKS
DI extracts authenticated global Verigence USER identity
DI -> Security authorization service using DI's ServiceIntegration identity
Security evaluates USER + Tenant + required DI permission
Security -> ALLOW / DENY
DI executes only if allowed
```

Audit Core may also invoke DI internally using the ServiceIntegration machine-token model defined in Section 31.

### 4.5 ServiceIntegration trust boundary — CONFIRMED

A service identity is trusted only after Security authenticates a registered confidential machine client and issues a short-lived signed JWT.

Target modules accept machine calls only from trusted Security-issued machine tokens that pass all applicable checks, including:

- Security issuer/signature;
- expiry;
- `actor_type = SERVICE_INTEGRATION`;
- expected target audience;
- registered service subject;
- required service permission.

An external system is not allowed merely because it can reach a module endpoint. Without a registered service credential and a valid Security-issued token for that target audience, the request is denied.

---

## 5. Web BFF boundary

### 5.1 Responsibilities — CONFIRMED

The BFF capability is part of the Web module and provides a stable frontend-facing surface for the Web application.

Typical Web BFF functions include:

- user-management screens;
- pending/active user views;
- approval/rejection actions;
- role-assignment screens;
- Tenant/Dealer-Outlet assignment orchestration;
- forwarding the Security-issued human authentication context to backend APIs;
- response composition where one UI view needs Security and Audit Core data.

The Web BFF does not call Clerk. Human signup/login credential operations are sent to Security's Verigence APIs.

### 5.2 Non-responsibilities — CONFIRMED

The Web BFF does not persist authoritative copies of USER, role, permission or Dealer/Outlet assignment records.

The Web BFF must not grant access merely because a UI control is shown or hidden.

Every backend module remains responsible for enforcing its own protected operation.

### 5.3 Deployment ownership — CONFIRMED

The BFF is **merged into the Web module**. No separate BFF Verigence module is introduced.

This design does not create an additional repository/service ownership boundary merely for the BFF capability.

Where the Web BFF performs true backend-to-backend calls that require machine authentication, it uses its own registered ServiceIntegration service identity; it must not share Audit Core or DI machine credentials.

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

### 7.1 Security-only human sign-in — CONFIRMED

Web/Mobile authenticates through Verigence Security APIs. There is no direct Web/Mobile-to-Clerk authentication path.

Conceptually:

```text
Web/Mobile
   |
   | identifier + password
   | optional Device/Geo request-context headers may also be present
   v
Security
   |
   | Clerk Backend API
   v
Clerk credential verification
   |
   v
Security resolves Clerk subject -> global Verigence USER
   |
   +-- USER must be ACTIVE
   +-- no Tenant, Device, Geo, Schedule or VPN gate in Phase-1 login
   v
Security issues Verigence human access JWT
```

`tenantId` is not accepted as part of the canonical login contract. Tenant context is supplied later to the relevant protected operation and is evaluated through live Security authorization.

Optional Device ID and Geo request-context headers are allowed to arrive from the client, but Phase 1 does not persist them, link them to login, or use them to decide authentication. Their absence does not block login.

Human credentials are transient request secrets. Security may pass them to Clerk Backend APIs over TLS for verification but must not persist, hash, audit, trace, cache or log them.

### 7.2 Security human-token validation — CONFIRMED

Backend boundaries receiving the Security-issued human access JWT validate it locally using Security's trusted signing keys/JWKS and the applicable human-token checks, including signature, issuer and expiry.

The human token identifies the authenticated global Verigence USER. It does not replace live Security authorization.

Audit Core and DI do not validate Clerk JWTs and require no Clerk keys.

### 7.3 Backend authorization hand-off — CONFIRMED

For human requests reaching Audit Core or DI:

1. the resource server validates the Security-issued human access JWT locally;
2. it extracts the trusted global Verigence USER identity from that token;
3. it calls Security's authorization service using its own registered `ServiceIntegration` machine identity/token;
4. it supplies the validated USER identity plus Tenant and required permission as authorization context;
5. Security trusts that USER context because it arrived from an authenticated registered service caller after local validation of a Security-signed human token.

A browser/client must never be allowed to supply an arbitrary `userId` directly to the internal authorization endpoint as proof of identity.

Security's own human-facing/admin APIs validate the Security-issued human access JWT and apply the same authorization logic in-process.

---

## 8. Phase-1 human token model

### 8.1 Security is the Verigence human token issuer — CONFIRMED

Clerk authenticates human credentials only behind Security's backend integration.

Security issues the human access JWT used inside Verigence after successful Clerk-backed authentication and USER/session policy checks.

The canonical human JWT identifies the global USER and is not bound to a `tenantId` at login. Tenant authorization is evaluated later from current Security state.

The target does not retain separate login/token models for ordinary USER versus PlatformAdmin; authentication is one human Security boundary and role/classification is an authorization concern.

### 8.2 Authorization claims are not the authority — CONFIRMED

Do not copy the authoritative Verigence role/permission database into the human token simply to make backend authorization local.

The Security-issued human access JWT is authentication/session evidence. Protected operations still use current Security authorization state.

### 8.3 No Clerk token introspection in Verigence modules — CONFIRMED

Web/Mobile, Web BFF, Audit Core and DI do not receive Clerk session tokens and do not introspect Clerk.

Security uses Clerk Backend APIs only for the credential/account operations that require Clerk. Ordinary downstream validation of an already-issued Verigence human access JWT uses Security signing/JWKS.

### 8.4 Existing Security human-token capability — EXISTING BUT MODIFY

Current Security runtime already contains Clerk-backend human login/access-session patterns and Security token signing capability.

The target retains one Security human authentication/token path, removes duplicate/legacy human login/token contracts, and keeps authoritative authorization live in Security rather than treating token permission claims as the source of truth.

Security signing/JWKS capability is also retained for approved machine/service authentication under `ServiceIntegration`; human and machine actor/token semantics remain distinct.

---

## 9. Human USER onboarding

### 9.1 Principle — CONFIRMED

Onboarding creates a global identity only.

It does not assign:

- Tenant;
- operating role;
- administrative role;
- Dealer/Outlet business assignment.

`TestUser` and the single SuperAdmin are pre-identified Phase-1 identities and are handled by their explicit bootstrap/configuration requirements rather than ordinary employee role assignment.

### 9.2 Platform-global onboarding gate — EXISTING AND RETAIN

The existing platform-global onboarding-key concept is compatible with global USER onboarding and can remain the Phase-1 submission gate unless separately changed.

The user-facing name is **Verigence Identifier**. The existing Security API carries this value through `X-Onboarding-Key`; this is an implementation/API name and does not change the user-facing label.

Possession of the onboarding key grants no application role, Tenant authorization or business access.

### 9.3 Target onboarding sequence

```text
1. Employee enters the global onboarding journey through Web/Mobile.

2. Web/Mobile submits first name, last name, email ID, mobile number and
   password to Security through the Verigence API, with the Verigence
   Identifier supplied through the existing X-Onboarding-Key contract.
   Optional Device ID / Geo request-context headers may also be present,
   but they are not required or persisted in Phase 1.

3. Security validates the permitted platform-global onboarding gate
   and duplicate global identity constraints.

4. Security creates/coordinates the Clerk human identity through the
   Clerk Backend API and initiates the approved email verification flow.
   Password/OTP values are transient and are never persisted or logged.

5. Employee submits the email verification value to Security through
   the Verigence API; Security verifies it with Clerk Backend APIs.

6. Security records/binds the resulting Clerk subject to exactly one
   global Verigence USER after validating the expected identity/email relationship.

7. USER remains PENDING.

8. Authorized administration can list PENDING users.

9. Administrator changes the USER to ACTIVE or REJECTED according to
   the approved lifecycle permission model.

10. Tenant/role/Dealer-Outlet configuration is performed separately after
    identity onboarding.
```

### 9.4 Existing Security password/OTP façade — EXISTING AND RETAIN WITH MODIFICATION

The existing Security-mediated Clerk signup/email-OTP approach matches the confirmed Security-only Clerk integration boundary and remains the implementation base where it already satisfies the approved global USER lifecycle.

The target must preserve these invariants:

- Web/Mobile never calls Clerk directly;
- only Security holds Clerk backend integration secrets;
- password/OTP values are transient and never persisted, audited, traced, cached or logged;
- TOTP/MFA is not required by the Phase-1 signup/login contract;
- optional Device ID / Geo request context does not become an onboarding/login persistence or access gate in Phase 1;
- Clerk verification success does not itself activate the Verigence USER;
- Security records the Clerk subject-to-USER mapping and keeps the USER `PENDING` until approval.

Provider-specific creation/verification safeguards already proven in the current backend integration should be reused rather than replaced without a separate approved reason.

### 9.5 Onboarding failure rules

- wrong/disabled onboarding gate -> no active USER access;
- duplicate global email -> do not create another USER;
- Clerk identity mismatch -> do not bind;
- Clerk creation/verification failure -> do not report onboarding verification success;
- successful Clerk verification -> USER still remains PENDING until Verigence approval;
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

REJECTED / SUSPENDED / DISABLED
   -> ACTIVE only by SuperAdmin

DISABLED
   -> hard DELETE by SuperAdmin
```

### 10.2 Status semantics

| Status | Meaning |
|---|---|
| `PENDING` | Global identity exists/bound sufficiently for review but is not approved for Verigence application access. |
| `REJECTED` | Onboarding/approval was rejected. No protected application access. |
| `ACTIVE` | USER is eligible for authorization decisions, subject to role/Tenant/permission rules. |
| `SUSPENDED` | USER is temporarily non-active. Protected authorization fails. |
| `DISABLED` | Account is disabled because hard deletion has been requested and is awaiting SuperAdmin hard-delete decision/execution. |

### 10.3 DELETE is not a status — CONFIRMED

Hard DELETE removes the live USER account after the deletion preconditions are met.

Only SuperAdmin may execute the hard DELETE.

### 10.4 Reactivation — CONFIRMED

In Phase 1, only SuperAdmin may reactivate an employee USER from a non-active lifecycle state back to `ACTIVE`.

This applies to reactivation from:

- `SUSPENDED`;
- `REJECTED`;
- `DISABLED`, where the deletion request is cancelled/reversed instead of being hard-deleted.

Every reactivation is an audited Security administration action.

---

## 11. Approval and rejection

### 11.1 Pending list — CONFIRMED

Security must expose a filterable global USER list capable of returning PENDING users for approval review.

### 11.2 Activation — CONFIRMED

Successful Clerk credential/email verification alone never activates a Verigence USER.

Activation is an explicit Security lifecycle decision.

### 11.3 Rejection — TARGET REQUIREMENT

The target USER status model includes `REJECTED`; the current implementation does not expose it in the global status API and must be modified.

The Security audit trail records the approving/rejecting actor, target USER, timestamp and reason where supplied.

### 11.4 Reactivation authority — CONFIRMED

Once an employee USER has entered `REJECTED`, `SUSPENDED` or `DISABLED`, only SuperAdmin can return the USER to `ACTIVE` in Phase 1.

---

## 12. Suspension and session enforcement

### 12.1 Security status is authoritative — CONFIRMED

Every authorization decision first requires USER status `ACTIVE`.

A cryptographically valid Security-issued human access JWT presented by a `SUSPENDED`, `DISABLED`, `PENDING` or `REJECTED` USER is insufficient for Verigence access.

### 12.2 Clerk lifecycle synchronization — EXISTING AND RETAIN WITH MODIFICATION

Existing Security design already synchronizes non-active USER lifecycle to Clerk by terminating/banning authentication capability as a defense-in-depth measure.

Target Phase 1 should preserve that concept for `SUSPENDED` and `DISABLED`, while Security status remains the immediate Verigence authorization authority.

If Clerk lifecycle synchronization is temporarily unavailable, Security remains fail-closed because the local USER status is already non-ACTIVE.

When SuperAdmin reactivates an employee, the corresponding Clerk lifecycle state must also be restored as required for that employee to authenticate again.

---

## 13. Maker/checker hard deletion

### 13.1 Maker rule — CONFIRMED

Deletion request may be initiated by:

- the USER themselves;
- Executive;
- TenantAdmin;
- ModuleAdmin;
- SuperAdmin.

The maker action does not hard-delete immediately.

It transitions the USER to `DISABLED`, terminates application access and records the deletion request/audit evidence.

### 13.2 Checker/final-delete rule — CONFIRMED

Only `SuperAdmin` may execute final hard deletion.

Phase 1 has only one SuperAdmin, and the same human may act as maker and checker. Therefore if the SuperAdmin initiates the deletion request, that same SuperAdmin may subsequently execute the final hard DELETE.

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
- caller is the active Phase-1 SuperAdmin;
- deletion-request evidence is present.

A different-human checker is not required in Phase 1.

### 13.4 Deletion workflow

```text
Maker
  |
  | request delete
  v
Security
  |
  +-- record deletion request + actor/time/reason
  +-- status -> DISABLED globally
  +-- revoke/terminate Verigence access across Tenants
  +-- terminate/disable Clerk authentication sessions/account access
  |
  v
Await SuperAdmin final decision
  |
  +-- reactivate instead -> SuperAdmin returns USER to ACTIVE
  |
  +-- hard DELETE
         v
Security deletion coordinator
  |
  +-- delete/retire Clerk live identity/account as required
  +-- remove live Security role/Tenant authorization assignments
  +-- remove live global USER identity/PII according to approved retention
  +-- release email for permitted reuse
  +-- preserve required historical audit reference/snapshot for the retention period
```

### 13.5 Global deletion request scope — CONFIRMED

USER deletion is **global and independent of Tenant context in Phase 1**.

A deletion request targets the global USER, not an individual Tenant assignment. If an allowed maker initiates the deletion request, the USER transitions to `DISABLED` globally and loses Verigence access across all Tenants.

The USER having authorization in other Tenants does not create a separate Tenant-specific deletion workflow or prevent the global deletion request.

Final hard deletion remains SuperAdmin-only.

### 13.6 Historical deletion/audit retention — CONFIRMED

Hard deletion of the live USER must not cascade-delete the retained Security/Audit evidence required for the deletion trail.

The default Phase-1 retention period for the retained deleted-user actor tombstone/snapshot and deletion audit reference is **21 days** after hard deletion.

The retained record must not depend on the live USER row continuing to exist and must not retain credentials, tokens or secrets.

---

## 14. Role taxonomy

### 14.1 Global human role catalogue — CONFIRMED

The human role definition catalogue is global.

Target human role classes:

| Classification | Role keys | Assignment nature |
|---|---|---|
| Operating | PC, TL, PM, CRM, Executive | Tenant-context assignment; exactly one operating role per USER/Tenant. |
| Administrative | ModuleAdmin, TenantAdmin, SuperAdmin | Administrative assignment; admin roles may stack but cannot coexist with any operating persona. |
| Test | TestUser | Controlled test identity assigned to TestTenant; functional privileges mirror PC for TestTenant. |

### 14.2 Machine classification — CONFIRMED

`ServiceIntegration` is machine-only and is not part of the human role catalogue.

Conceptually:

```text
actor_type = SERVICE_INTEGRATION
service_id = audit-core | di | web | future registered service
```

A ServiceIntegration principal is authorized through registered service audiences and service permissions rather than human Tenant operating-role assignment.

### 14.3 Tenant does not create role identity — CONFIRMED

`PC` in Tenant A and `PC` in Tenant B are the same global role classification.

What differs by Tenant is the approved functional permission mapping.

### 14.4 Role names are not runtime permission checks — CONFIRMED

Business APIs authorize using required permission keys evaluated by Security.

The operating role may be returned for administration/audit/UI context, but modules must not replace permission checks with `if role == ...` logic.

### 14.5 Role-aligned Groups — CONFIRMED

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

The single SuperAdmin remains an administrative persona even though Phase 1 grants SuperAdmin all ACTIVE functional permissions.

### 16.2 Administrative-role stacking — CONFIRMED

`ModuleAdmin` and `TenantAdmin` may coexist.

`SuperAdmin` may coexist with `ModuleAdmin` and/or `TenantAdmin`, although Phase 1 has only one SuperAdmin.

### 16.3 TenantAdmin — CONFIRMED

`TenantAdmin` administers **one Tenant across modules**.

Conceptually:

```text
TenantAdmin(T1)
    -> Security administration for T1
    -> Audit Core administration for T1
    -> DI administration/configuration for T1
    -> no authority over T2 unless separately assigned TenantAdmin(T2)
```

Phase-1 TenantAdmin responsibilities include the administration tasks already agreed for the assigned Tenant:

- view the assigned Tenant and its user population;
- view PENDING/ACTIVE/non-active users where the applicable Security permission permits;
- assign/change/remove operating roles for users in that Tenant;
- view the role-aligned PC/TL/PM/CRM/Executive Groups for that Tenant;
- view registered module permissions and the Tenant's current role bundles;
- administer module configuration/tasks within that Tenant using the applicable module-admin permissions;
- read Tenant-scoped Security/audit information where permission is granted;
- suspend or request deletion according to the approved lifecycle/deletion rules.

TenantAdmin **does not modify the Tenant's role-to-permission bundle in Phase 1**. Tenant role-bundle changes are SuperAdmin responsibility.

TenantAdmin is Tenant-scoped for normal administration. USER deletion is the explicit Phase-1 exception: deletion requests target the global USER and are not Tenant-scoped.

### 16.4 ModuleAdmin — CONFIRMED

`ModuleAdmin` administers **one module across Tenants**.

Conceptually:

```text
ModuleAdmin(AUDIT)
    -> Audit Core administration across Tenants

ModuleAdmin(DI)
    -> DI administration across Tenants
```

A ModuleAdmin does not receive operating-user permissions merely because they administer the module. Administrative permissions remain distinct from PC/TL/PM/CRM/Executive functional bundles.

#### Audit Core ModuleAdmin default administration permissions

The Phase-1 Audit Core ModuleAdmin default uses the already identified Audit Core administrative capabilities:

- `audit.project.read`
- `audit.project.update`
- `audit.project.assignment.manage`
- `audit.master.read`
- `audit.master.write`
- `audit.master.publish`
- `audit.analytics.read`
- `audit.audit_trail.read`

Any additional Audit Core `*.manage` capability must be added only when explicitly approved as a ModuleAdmin function; it is not inferred automatically.

#### DI ModuleAdmin default administration permissions

The Phase-1 DI ModuleAdmin default uses the already identified DI configuration/administration capabilities:

- `di.requirement_profile.read`
- `di.requirement_profile.write`
- `di.requirement_profile.publish`
- `di.requirement_profile.assign`
- `di.extraction_config.read`
- `di.extraction_config.write`
- `di.extraction_config.publish`
- `di.quality_config.read`
- `di.quality_config.write`
- `di.tenant_config.read`
- `di.tenant_config.write`
- `di.operations.read`

ModuleAdmin does not automatically receive document upload/delete, verification-write, or other operating-user capabilities unless those are separately approved as required administrative capabilities.

### 16.5 SuperAdmin — CONFIRMED

Phase 1 has one SuperAdmin only.

SuperAdmin has every ACTIVE permission in Security's registered permission catalogue across all modules. The permission grant remains synchronized as module catalogues evolve so that newly ACTIVE permissions are also available to the SuperAdmin by default.

This extends the useful existing `platform.super_admin` full-authority invariant beyond Security-only permissions to all registered module permissions in the target design.

No separate Tenant operating role is required for SuperAdmin.

---

## 17. TestUser and TestTenant

### 17.1 Purpose — CONFIRMED

`TestUser` exists for controlled Phase-1 testing.

### 17.2 Clerk identity — CONFIRMED AS SUPPLIED

The Clerk subject supplied for the TestUser is:

```text
user_3I7H…eXFRoeoud
```

Implementation requires the complete exact subject if the ellipsis is a redaction.

### 17.3 TestTenant — CONFIRMED

A canonical `TestTenant` must exist and be recognized in:

- Security;
- Audit Core;
- DI.

Security is the authority for the canonical TestTenant identity. The same Tenant ID is propagated/used by dependent module representations.

### 17.4 TestUser permission bundle — CONFIRMED

TestUser is assigned to TestTenant and receives the same functional privileges as `PC` in TestTenant.

Conceptually:

```text
TestUser
   -> TestTenant
   -> effective functional bundle = TestTenant / PC bundle
```

This avoids a separately drifting TestUser permission list.

### 17.5 Isolation — CONFIRMED

TestUser remains a test classification and is not assigned operating/admin roles in production Tenants in Phase 1.

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

TestUser is handled through its dedicated TestTenant assignment and does not participate in production Tenant operating-role cardinality.

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
        +------------------------------+
        |                              |
        v                              v
SuperAdmin automatically      Admin UI/API can list
receives ACTIVE permission    modules + permissions
        |                              |
        |                              v
        |                    Security shows Tenant role bundle
        |                              |
        |                              v
        |                    SuperAdmin keeps default or changes bundle
        |                              |
        +------------------------------+
                                       |
                                       v
                              role assigned to USER
```

A role-permission mapping must reference permission keys that exist and are ACTIVE in the registered module catalogue. Security must not allow an arbitrary unregistered permission string to be mapped to a role bundle.

### 20.3 Existing module catalogue — EXISTING AND RETAIN

Current Security already provides a Platform Module Catalogue surface and persists module permissions/templates. This is aligned with the target and should be retained, subject to role-model changes described below.

### 20.4 Permission retirement — EXISTING AND RETAIN

Existing catalogue logic detects conflicts when a permission is still referenced by role configuration. That safety behaviour remains valuable.

For SuperAdmin, an inactive/retired permission is removed from the automatic all-ACTIVE-permission grant.

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

### 21.7 Executive default bundle — CONFIRMED

`Executive` is Tenant-wide.

The agreed Phase-1 default is:

**Audit Core**

- all approved/current Audit Core read capabilities;
- normal non-destructive Audit Core update/write capabilities.

The Executive default excludes capabilities whose semantics are stronger than read/update/write, including create, delete, upload, submit, verify, decide, resolve, execute, publish and administrative `manage` actions unless separately added by an explicit later decision.

**DI**

- read-only DI capabilities by default;
- no DI configuration write/publish/assign capability by default.

This preserves Executive visibility and normal Audit updates without making Executive a DI configuration administrator.

### 21.8 TestUser default bundle — CONFIRMED

`TestUser` does not maintain an independent default bundle.

For `TestTenant`:

```text
TestUser effective permissions = TestTenant PC permission bundle
```

The initial TestTenant PC bundle is seeded from the approved PC platform default in Section 21.6.

### 21.9 SuperAdmin bundle — CONFIRMED

SuperAdmin is not seeded from an operating-role default.

```text
SuperAdmin effective functional/admin permissions
    = every ACTIVE registered permission across all modules
```

The grant follows the active Security permission catalogue and is platform-wide.

### 21.10 Default seed and Tenant override flow — CONFIRMED

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

## 22. Runtime human authorization

### 22.1 Security is the Policy Decision Point — CONFIRMED

For Phase 1, Security is synchronously called for every protected backend request requiring Verigence functional authorization.

Normal Audit Core/DI human request flow:

```text
Human Client
  |
  | Security-issued human access JWT
  v
Resource Server (Audit Core / DI)
  |
  +-- validate Security human JWT locally using Security signing/JWKS
  |
  +-- extract validated global Verigence USER identity
  |
  +-- determine required canonical permission
  |
  +-- call Security authorization service
  |      Authorization: Bearer <caller ServiceIntegration JWT>
  |      userId + tenantId + required permission
  |
  |      Security:
  |        validate caller ServiceIntegration JWT
  |        verify caller is registered/ACTIVE and allowed to use AuthZ API
  |        trust userId only from this authenticated service caller
  |        USER must exist and status == ACTIVE
  |        Tenant active where applicable
  |        resolve USER operating/admin/test context
  |        resolve applicable permission bundle
  |        evaluate required permission
  |        return ALLOW/DENY + stable decision context
  |
  +-- if Audit Core, additionally evaluate Dealer/Outlet business scope where applicable
  |
  +-- execute operation
```

The role-aligned Group does not add permissions at runtime. It is the USER collection corresponding to the same operating role and same Tenant permission bundle.

### 22.2 Authorization API — TARGET

Conceptual internal API:

```text
POST /security/v1/authorization/check
Authorization: Bearer <Security-issued ServiceIntegration JWT>
```

Conceptual request:

```json
{
  "userId": "<global-verigence-user-id extracted from a validated Security human JWT>",
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

For admin/test identities the response context may identify the applicable classification rather than an operating role.

### 22.3 No arbitrary user identity trust — CONFIRMED

The authorization endpoint accepts `userId` only from an authenticated registered ServiceIntegration caller that derived it from a locally validated Security-issued human access JWT.

A client/browser cannot call the internal authorization endpoint and establish identity merely by sending a `userId` value.

Resource servers must strip/ignore client-provided internal identity-context headers and construct the authorization request from the Security human token they themselves validated.

### 22.4 Internal caller protection — CONFIRMED

Security's authorization endpoint requires an approved ServiceIntegration machine token for backend callers.

The calling service principal must be:

- registered in Security;
- ACTIVE;
- authorized for Security as a target audience;
- authorized to invoke the authorization-check service capability.

### 22.5 Security's own human/admin APIs

Security administration endpoints do not make a network call back into Security.

Security validates its own human access JWT and applies the same authorization logic in-process.

### 22.6 Failure rule — CONFIRMED

If Security is unavailable or cannot produce a trustworthy authorization decision, the protected backend operation fails closed.

No cached human allow result is required in Phase 1.

### 22.7 Future optimization — DEFERRED

Do not introduce projections, local replicated permission stores, human-token permission claims or long-lived authorization caches until measured performance/availability shows a need.

---

## 23. Dealer/Outlet assignment boundary

### 23.1 Security does not own Dealer/Outlet assignment — CONFIRMED

Security authorization ends at the functional permission decision.

Dealer/Outlet association is an Audit Core business assignment.

### 23.2 Phase-1 Dealer/Outlet associations — CONFIRMED

For Phase 1, **Dealer is the Outlet** for implementation and user business-scope assignment. The system does not maintain a separate Dealer assignment and a second Outlet restriction for the same user.

Audit Core must be able to associate relevant operating users with Dealer/Outlet entities:

- PC
- TL
- PM
- CRM

No Phase-1 cardinality ratio is enforced.

### 23.3 Executive — CONFIRMED

Executive is Tenant-wide and does not require Dealer/Outlet assignment.

### 23.4 No separate Outlet model in Phase 1 — CONFIRMED

There is no additional USER-to-Outlet restriction layer beyond the Dealer/Outlet assignment described above.

### 23.5 Web BFF orchestration

A UI may present one assignment operation containing role and Dealer/Outlet selection.

Web BFF orchestration may perform:

```text
1. Security: set USER/Tenant operating role
2. Audit Core: set/create Dealer/Outlet association
```

Each system remains authoritative for its own write.

If Security succeeds and Dealer/Outlet association fails, no Dealer/Outlet-scoped business access is granted merely because the role exists; Audit Core fails its local business-scope check.

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

Returns Security-owned USER lifecycle/identity metadata only. Dealer/Outlet assignments are not embedded as Security-owned fields.

### 24.3 Status change — TARGET

```text
PATCH /security/v1/users/{userId}/status
```

The authorization policy distinguishes:

- ordinary approval/rejection administration;
- suspension;
- self-delete request;
- Executive/TenantAdmin/ModuleAdmin/SuperAdmin global delete request;
- SuperAdmin-only reactivation from REJECTED/SUSPENDED/DISABLED to ACTIVE.

### 24.4 Hard delete — TARGET

```text
DELETE /security/v1/platform/users/{userId}
```

Only the one active Phase-1 SuperAdmin may execute this operation, subject to the confirmed deletion preconditions.

---

## 25. Role, Group and administrative APIs

### 25.1 Global role catalogue — TARGET

```text
GET /security/v1/roles
```

Phase-1 human catalogue is fixed to approved classifications rather than allowing each Tenant to create business role identities.

`ServiceIntegration` is returned/managed through the machine/service administration surface rather than as an assignable human role.

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

### 25.5 TenantAdmin assignment — TARGET SEMANTICS

TenantAdmin assignment is Tenant-scoped.

Conceptually:

```text
PUT /security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin
DELETE /security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin
```

The exact URI may be normalized during OpenAPI design, but the scope semantics are fixed: TenantAdmin applies only to the assigned Tenant and spans modules for that Tenant.

### 25.6 ModuleAdmin assignment — TARGET SEMANTICS

ModuleAdmin assignment is module-scoped across Tenants.

Conceptually:

```text
PUT /security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin
DELETE /security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin
```

The exact URI may be normalized during OpenAPI design, but the scope semantics are fixed.

### 25.7 SuperAdmin assignment — PHASE-1 FIXED

There is exactly one active SuperAdmin in Phase 1.

The existing Clerk identity supplied in Section 2.6 is the designated Phase-1 SuperAdmin identity. No API to create/assign a second SuperAdmin is required in Phase 1.

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

Phase 1 has approved default behavior for:

- PC;
- TL;
- PM;
- CRM;
- Executive;
- TestUser via the TestTenant PC bundle;
- SuperAdmin via all ACTIVE registered permissions.

### 26.3 Tenant role bundle — TARGET

Replace Tenant role creation with Tenant configuration of the permission bundle for a global role classification.

Conceptual APIs:

```text
GET /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
PUT /security/v1/tenants/{tenantId}/role-bundles/{roleKey}
```

The PUT replaces the approved permission set for that role/Tenant atomically after validating that every permission exists and is active in an approved module catalogue.

The API does not create a new role identity.

Only SuperAdmin changes Tenant role bundles in Phase 1.

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

### 27.2 User role + Dealer/Outlet assignment

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

`dealerIds` represents the Phase-1 Dealer/Outlet business entity; a second Outlet assignment is not required.

Web BFF orchestrates Security + Audit Core but stores neither record.

The actual Dealer/Outlet cardinality is not constrained in Phase 1.

The corresponding Security role-aligned Group membership is updated automatically by the role assignment; the Web BFF does not need a second Group-membership write.

### 27.3 Partial-failure behaviour

The Web BFF must report partial failure accurately and must not fabricate a combined success.

Backends remain fail-safe because Security functional role alone does not satisfy Audit Core Dealer/Outlet business-scope checks.

---

## 28. Security audit trail

### 28.1 Required authoritative events — CONFIRMED

Security records authoritative audit evidence for at least:

- onboarding request;
- Clerk identity creation/binding outcome without credential/OTP material;
- human login/authentication security events without credential material;
- USER approval;
- USER rejection;
- USER activation/reactivation;
- suspension;
- deletion request / transition to DISABLED;
- SuperAdmin hard delete;
- operating-role assignment/change/removal;
- resulting role-aligned Group membership change;
- administrative-role assignment/change/removal;
- Tenant role-bundle permission changes;
- module permission-catalogue changes;
- Tenant authorization changes;
- SuperAdmin permission-catalog synchronization changes where material;
- service-client registration/status/credential-rotation events;
- ServiceIntegration token issuance failures and security-relevant machine-authentication failures;
- important human authentication/lifecycle synchronization failures.

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

Never store credentials, Clerk session tokens, Security human JWTs, service client secrets, service JWTs, passwords, OTP values or other secrets in audit records.

### 28.3 Hard-delete audit — CONFIRMED

Hard deletion must leave enough non-credential audit evidence to prove:

- who requested deletion;
- when the USER was disabled;
- who executed final hard deletion;
- when final deletion occurred;
- outcome/correlation identifiers.

The retained deleted-user actor tombstone/snapshot and deletion audit reference have a default Phase-1 retention period of **21 days after hard deletion**.

The retained audit reference must not depend on the deleted live USER row continuing to exist.

---

## 29. Session/status enforcement

### 29.1 Every human authorization request checks live USER status — CONFIRMED

Because Security is called synchronously for each protected human request, status changes take effect on the next authorization decision even if an already-issued Security human access JWT has not yet expired.

### 29.2 Role and permission changes — CONFIRMED TARGET EFFECT

Because permissions are resolved by Security at authorization time, changing a USER's role or a Tenant role bundle affects subsequent protected requests without reissuing the Security human access JWT.

Role-aligned Group membership follows the role assignment and has no independent authorization cache.

### 29.3 Human token still valid after Security suspension

Even if a Security-issued human access JWT remains cryptographically valid, Security denies the USER because status is no longer ACTIVE.

Clerk lifecycle termination/ban remains defense in depth and remaining live Security sessions/tokens should be revoked/invalidated according to the retained session capability where available.

### 29.4 Reactivation — CONFIRMED

Only SuperAdmin can return an employee from REJECTED/SUSPENDED/DISABLED to ACTIVE in Phase 1.

---

## 30. Audit Core integration

### 30.1 Human authentication and authorization contract — TARGET

Audit Core must trust the Security-issued **human** access JWT for authenticated Verigence USER identity, not integrate with Clerk.

Target human request contract:

```text
Client/Web BFF -> Audit Core: Security-issued human access JWT
Audit Core: validate Security human JWT locally using Security trusted signing/JWKS
Audit Core: extract validated global Verigence USER identity
Audit Core -> Security: ServiceIntegration JWT + USER identity + Tenant + required permission
Security: synchronous human authorization decision
Audit Core: evaluate Dealer/Outlet business scope locally
```

### 30.2 Functional authorization authority — RETAIN

Security remains the sole functional authorization authority.

### 30.3 Business scope authority — RETAIN

Audit Core remains the Dealer/Outlet business-scope authority. Dealer and Outlet are the same Phase-1 assignment concept.

### 30.4 Default operational permission bundles — EXISTING AND RETAIN AS SECURITY DEFAULT SOURCE

Audit Core already contains an approved `PC/TL/PM/CRM` default cross-module bundle covering Audit Core and DI permissions. Security uses those approved values as the Phase-1 platform defaults listed in Section 21.6.

This does not transfer permission ownership to Audit Core; Audit Core owns its permission catalogue while Security owns the default/Tenant role mapping used for authorization.

### 30.5 Existing Audit Core design alignment requirement

Current Audit Core design states that it verifies Security-issued JWTs through Security JWKS and authorizes human users from `permissions[]` claims.

The Security-issued human JWT/JWKS trust direction remains valid, but authoritative permission evaluation must move to synchronous Security authorization instead of trusting embedded `permissions[]` as the authorization source of truth.

No Clerk integration is introduced into Audit Core.

No Audit Core file is changed by this Security design work.

---

## 31. DI and ServiceIntegration boundary

### 31.1 Direct human DI access — CONFIRMED

Human users may call DI directly for approved DI capabilities.

DI does **not** perform human onboarding, role assignment or USER lifecycle management and does not integrate with Clerk.

For direct protected human access:

```text
Human -> DI with Security-issued human access JWT
DI validates Security human JWT locally using Security trusted signing/JWKS
DI extracts validated global Verigence USER identity
DI -> Security authorization/check using DI ServiceIntegration JWT
Security evaluates ACTIVE USER + Tenant/role/permission
DI executes only after ALLOW
```

The Security human JWT is authentication evidence at DI; DI does not derive Verigence permission merely from the existence of a valid human token.

### 31.2 Machine token issuer — CONFIRMED

**Verigence Security is the machine-token issuer.**

Clerk is not used for ServiceIntegration machine authentication.

Security maintains registered confidential service clients such as, conceptually:

```text
audit-core-service
web-service
di-service
future approved internal services
```

Each service registration contains the Security-owned information required to authenticate and constrain the service, conceptually including:

```text
service_id / client_id
client_secret_hash or approved machine credential reference
status = ACTIVE/INACTIVE
role/classification = ServiceIntegration
allowed target audiences
allowed integration permissions
credential metadata/rotation state
```

Plaintext long-lived service secrets are not stored as readable application data.

### 31.3 Machine-token issuance flow — CONFIRMED

Conceptual token endpoint:

```text
POST /security/v1/service/token
```

A registered service authenticates to Security using its confidential machine credentials and requests a token for an allowed target audience.

Example:

```text
Audit Core
   |
   | client identity + secret/approved machine credential
   | requested audience = di
   v
Security
   |
   +-- service registered?
   +-- credential valid?
   +-- service ACTIVE?
   +-- ServiceIntegration classification?
   +-- audience di allowed for this service?
   +-- requested service permissions allowed?
   |
   v
issue short-lived signed service JWT
```

The machine token is short-lived. The exact configured TTL is finalized during implementation within the agreed short-lived service-token model; no long-lived bearer service token is required.

No refresh-token mechanism is required for the Phase-1 service flow; a service obtains another short-lived machine token from Security when needed.

### 31.4 Machine JWT semantics — CONFIRMED

Conceptually:

```json
{
  "iss": "verigence-security",
  "sub": "service:audit-core",
  "actor_type": "SERVICE_INTEGRATION",
  "aud": "di",
  "exp": "<short-lived-expiry>",
  "permissions": [
    "<approved-service-permission>"
  ]
}
```

Exact claim naming follows the existing approved Security machine-token conventions where possible.

### 31.5 Target-module validation — CONFIRMED

A target module such as DI validates a ServiceIntegration JWT locally using Security's trusted machine-token signing keys/JWKS.

At minimum it rejects unless:

- token signature is valid;
- issuer is the trusted Verigence Security machine-token issuer;
- token is not expired;
- `actor_type` is `SERVICE_INTEGRATION`;
- audience contains the receiving module, for example `di`;
- service subject is valid for the expected machine model;
- required service permission is present.

A token issued for audience `security` cannot be replayed as a valid DI token merely because it was otherwise signed by Security.

### 31.6 Service-specific least privilege — CONFIRMED

There is one `ServiceIntegration` machine classification, but service principals do not automatically receive universal cross-module permissions.

For example:

```text
audit-core-service
  ServiceIntegration
  allowed audiences: security, di
  permissions: only approved Audit Core integration needs

web-service
  ServiceIntegration
  allowed audiences: security, audit-core, other explicitly approved targets
  permissions: only approved Web/BFF integration needs

di-service
  ServiceIntegration
  allowed audiences: security and other explicitly approved targets
  permissions: only approved DI integration needs
```

Compromise of one service principal must not automatically confer every module permission.

### 31.7 Blocking external systems — CONFIRMED

An external system is denied unless it has been deliberately registered as an approved service client and receives a valid target-audience machine token from Security.

Examples:

```text
External -> DI with no token
    -> 401 / deny

External -> DI with self-signed/fake JWT
    -> invalid signature / issuer -> deny

External -> DI with Security JWT for aud=security
    -> audience mismatch -> deny

External -> Security token endpoint with unknown client_id
    -> invalid client -> deny

External -> Security token endpoint with known client_id but wrong secret
    -> invalid client credential -> deny
```

Network/API-gateway restrictions may provide additional defense in depth, but network reachability alone never grants module access.

mTLS may be evaluated later if required; it is not required for the Phase-1 design.

### 31.8 Audit Core -> DI — CONFIRMED

Minimum internal target flow:

```text
Human -> Audit Core
   Security human JWT + Security human authorization
        |
        v
Audit Core needs DI capability
        |
        v
Audit Core obtains/uses short-lived Security ServiceIntegration JWT
   sub = service:audit-core
   aud = di
        |
        v
Audit Core -> DI
        |
        v
DI locally validates service JWT + required service permission
```

DI does not need the human token in order to authenticate Audit Core as a machine caller.

### 31.9 Human provenance — CONFIRMED

When a human-triggered Audit Core action causes a DI call, Audit Core retains the initiating global USER identity in its authoritative audit/business history and may pass safe provenance context to DI when needed.

DI trusts such provenance context only from an authenticated ServiceIntegration caller; it must not treat arbitrary client-provided provenance headers as authentication or authorization.

### 31.10 Delegated user token exchange — DEFERRED

No sophisticated user-on-behalf-of token exchange is required in Phase 1.

### 31.11 Existing DI design alignment requirement

Current DI Security-alignment design expects Security-issued USER JWTs for human authorization.

The Security-issued human JWT/JWKS trust direction remains valid. DI must use the token for authenticated USER identity and obtain the authoritative permission decision synchronously from Security rather than treating embedded human permission claims as the source of truth.

No Clerk integration is introduced into DI.

No DI file is changed by this Security design work.

---

## 32. Failure handling and fail-closed rules

### 32.1 Human login/Verigence token invalid

Security denies login when Clerk-backed credential verification fails.

Resource servers deny a protected request when the Security-issued human JWT is missing, invalid, expired or signed by an untrusted key.

### 32.2 Security human JWT valid but no live/ACTIVE Verigence USER

Security human authorization denies.

### 32.3 USER not ACTIVE

Security human authorization denies.

### 32.4 Tenant not ACTIVE / no Tenant role

Tenant-scoped authorization denies.

### 32.5 Permission absent from current Tenant role bundle

Security authorization denies.

### 32.6 Security unavailable

Protected human business requests requiring Security authorization fail closed. Phase 1 does not use stale local human authorization as an allow fallback.

A service unable to obtain/renew a required ServiceIntegration token also fails closed for that integration operation.

### 32.7 Audit Core Dealer/Outlet association absent

Audit Core denies Dealer/Outlet-scoped business action even if Security functional permission is allowed.

### 32.8 Role assignment conflicts

Security rejects:

- second active operating role for same USER/Tenant;
- second active PM in same Tenant;
- admin role assigned to a USER with any active operating persona;
- operating role assigned to a USER with any administrative persona.

The role-aligned Group representation cannot bypass these checks because Group membership is derived from the operating-role assignment.

### 32.9 Invalid ServiceIntegration token

Target modules fail closed when a machine token has any of the following conditions:

- invalid/untrusted signature;
- wrong issuer;
- expired token;
- wrong audience;
- wrong actor type;
- missing required service permission;
- inactive/unapproved service context where enforced.

### 32.10 Hard-delete dependency failure

If final deletion cannot complete safely across required live identity stores, Security must record failure and avoid reporting hard-delete success.

Exact compensation/retry ordering with Clerk is finalized in implementation design while preserving the confirmed 21-day deleted-user audit/tombstone retention rule.

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

No new Device/Geo persistence is added for onboarding/login in Phase 1. Existing Device/Geo schema remains available for future controls but is not repurposed to tag the global signup/login records.

### 33.3 Role definitions

```text
security.role_definitions
  role_key
  role_class: OPERATING | ADMIN | TEST
  display_name
  status
```

Phase-1 fixed human keys include:

- PC
- TL
- PM
- CRM
- Executive
- ModuleAdmin
- TenantAdmin
- SuperAdmin
- TestUser

`ServiceIntegration` is machine-only and is represented in the service identity model rather than a human `role_definitions` assignment.

### 33.4 Platform default role permissions

```text
security.platform_role_permission_defaults
  role_key
  permission_key
  source_catalog_version
  status
```

Phase-1 default behavior exists for:

- PC;
- TL;
- PM;
- CRM;
- Executive;
- TestUser through TestTenant's PC bundle.

SuperAdmin uses all ACTIVE registered permissions rather than a normal operating-role default rowset.

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
  scope_type: PLATFORM | TENANT | MODULE
  scope_id
  status
  assigned_by_user_id
  assigned_at_utc
```

Target scope semantics:

```text
SuperAdmin  -> PLATFORM, exactly one ACTIVE Phase-1 subject
TenantAdmin -> TENANT + tenant_id
ModuleAdmin -> MODULE + module_key
```

### 33.8 TestUser/TestTenant

Conceptually Security maintains:

```text
TestTenant
  canonical tenant_id
  tenant classification/marker as approved for test use

TestUser
  Clerk external identity
  test classification
  assigned TestTenant tenant_id
  effective bundle reference = TestTenant PC bundle
```

Audit Core and DI use the same canonical TestTenant ID in their module-specific representations.

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

### 33.11 ServiceIntegration registry — TARGET

Conceptually:

```text
security.service_clients
  service_id
  client_id
  credential_hash_or_reference
  status
  created_at_utc
  updated_at_utc
```

```text
security.service_client_audiences
  service_id
  audience
```

```text
security.service_client_permissions
  service_id
  permission_key
  target_module
```

Exact physical naming may reuse existing machine/service identity tables where those already satisfy the target semantics.

### 33.12 Deletion requests

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

This preserves maker/checker evidence separately from the live USER status. Phase 1 permits `requested_by_user_id = checked_by_user_id` when the actor is SuperAdmin.

Deletion requests are global USER operations and are not keyed/scoped by Tenant in Phase 1.

### 33.13 Security audit

Retain/extend the existing immutable administrative/security event/change-record concept so it can survive live USER hard deletion without cascade loss.

The deleted-user actor tombstone/snapshot and deletion audit reference are retained by default for **21 days after hard deletion**.

### 33.14 Objects not used as Phase-1 human authorization gates

- `tenant_memberships`
- current arbitrary Group-to-role additive grants
- current Group-derived permission union
- per-user human token permission/authorization snapshots as an alternative to live Security authorization

Existing Group data/API implementation may be reused only after it is constrained to the role-aligned Group semantics above; the current arbitrary additive RBAC behaviour is not retained.

Historical tables need not be destructively dropped merely because they leave the active runtime model.

---

## 34. Target API contract summary

Exact OpenAPI definitions follow design approval. Target semantic surface:

### Authentication / onboarding

```text
POST /security/v1/onboarding/users
POST /security/v1/onboarding/users/{signupAttemptId}/verify-email
POST /security/v1/onboarding/users/{signupAttemptId}/resend-email-code
POST /security/v1/auth/login
POST /security/v1/auth/precheck                       # optional existing UX gate
```

Canonical signup input:

```text
Body:
  firstName
  lastName
  email
  mobile
  password

Header:
  X-Onboarding-Key = user-facing Verigence Identifier

Optional request context:
  Device ID / Geo headers may be sent, but are not required, persisted or enforced in Phase 1.
```

Canonical login input:

```text
Body:
  identifier
  password

Not part of login:
  tenantId
  TOTP/MFA

Optional request context:
  Device ID / Geo headers may be sent, but are not required, persisted or enforced in Phase 1.
```

All human credential/email-verification interactions are Verigence-to-Security calls. Security alone brokers the required Clerk Backend API operations.

There is no direct Web/Mobile Clerk integration and no client-driven Clerk `/bind` operation in the target flow.

The same human login endpoint applies to ordinary USER, TestUser and human administrative classifications; authorization classification does not create a second authentication mechanism.

### USER administration

```text
GET    /security/v1/platform/users
GET    /security/v1/platform/users/{userId}
PATCH  /security/v1/users/{userId}/status
DELETE /security/v1/platform/users/{userId}
```

USER deletion/status-disable operations are global and do not require a Tenant identifier in Phase 1.

### Operating-role administration

```text
PUT    /security/v1/tenants/{tenantId}/users/{userId}/operating-role
DELETE /security/v1/tenants/{tenantId}/users/{userId}/operating-role
```

### Administrative-role administration

```text
PUT    /security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin
DELETE /security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin

PUT    /security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin
DELETE /security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin
```

No second-SuperAdmin assignment API is required in Phase 1.

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

### Human runtime authorization

```text
POST /security/v1/authorization/check
# backend caller authenticates with ServiceIntegration JWT
# userId is derived from a validated Security-issued human access JWT
```

### ServiceIntegration / machine authentication

```text
POST /security/v1/service/token
```

Service-client administration requires a Security administrative surface during implementation; exact CRUD URI naming is finalized with OpenAPI, while the service registry/audience/permission semantics in Section 31 are fixed.

### Module / permission catalogue

```text
GET /security/v1/platform/modules
GET /security/v1/platform/modules/{moduleKey}
GET /security/v1/platform/modules/{moduleKey}/permissions
PUT /security/v1/platform/modules/{moduleKey}/catalog
```

### Tenant administration

Existing Tenant entity/lifecycle APIs remain valuable. SuperAdmin has platform-wide authority in Phase 1. TenantAdmin administration is scoped to its assigned Tenant except for the confirmed global USER deletion-request capability.

---

## 35. Current -> Target gap analysis

| Area | Current `dev` | Target | Classification |
|---|---|---|---|
| Global USER | v1.4.2 global USER/onboarding exists. | One global USER, no per-Tenant re-onboarding. | **EXISTING AND RETAIN** |
| Clerk external identity mapping | Exists. | Clerk subject maps to one global USER. | **EXISTING AND RETAIN** |
| Global onboarding gate | Platform-global onboarding key exists. | Global gate remains; no Tenant/role/Dealer-Outlet during onboarding. | **EXISTING AND RETAIN** |
| Credential handling in Security | Current onboarding/login APIs accept password/TOTP/OTP and broker Clerk Backend APIs. | Retain Security-only Clerk Backend facade; keep secrets transient and never persisted/logged; no direct Web/Mobile Clerk integration. | **EXISTING AND RETAIN WITH MODIFICATION** |
| Canonical login request | Current `/auth/login` requires Tenant/Device/Geo and optionally TOTP because it is coupled to the legacy Tenant access-session path. | `identifier + password` only; no `tenantId`; optional Device/Geo request headers may arrive but are not persisted or gating. | **MODIFY ACTIVE LOGIN CONTRACT** |
| MFA | Current code/design includes TOTP/MFA concepts. | No Phase-1 MFA requirement. | **DEFERRED** |
| Device/Geo persistence at signup/login | Existing Device/Geo schema is Tenant/access-session oriented. | Do not tag onboarding/login with Device/Geo in Phase 1; no schema change is required for the global signup/login correction. | **DEFERRED FROM ACTIVE LOGIN/ONBOARDING** |
| USER statuses | Current status surface includes ACTIVE/SUSPENDED/DISABLED/EXITED; PENDING exists in onboarding. | PENDING/REJECTED/ACTIVE/SUSPENDED/DISABLED; hard DELETE separate. | **EXISTING BUT MODIFY** |
| REJECTED lifecycle | Not part of current global status request. | Required; SuperAdmin-only reactivation after rejection. | **NEW/MODIFY** |
| Hard USER deletion | No confirmed target maker/checker global hard-delete API in current global USER surface. | Global Tenant-independent DISABLED maker state + SuperAdmin-only final DELETE; same-person maker/checker allowed for SuperAdmin in Phase 1. | **NEW/MODIFY** |
| Hard-delete retention | Exact retained actor/deletion reference period was not fixed. | Default retained deleted-user tombstone/snapshot and deletion audit reference = 21 days after hard deletion. | **NEW TARGET RULE** |
| Reactivation | Current lifecycle does not implement the new confirmed authority rule. | REJECTED/SUSPENDED/DISABLED -> ACTIVE only by SuperAdmin. | **NEW/MODIFY** |
| Tenant membership | Historical/current tables remain, some legacy code still references them. v1.4.2 says no runtime membership prerequisite. | No membership authorization gate. | **RETIRE FROM RUNTIME** |
| Role definition | Current `security.roles` are Tenant-owned rows. | Global fixed role classifications. | **EXISTING BUT MODIFY** |
| Tenant role creation API | Current `/admin/tenants/{tenantId}/roles` creates arbitrary Tenant roles. | Tenant configures permission bundle for approved global role keys. | **RETIRE/REPLACE** |
| Operating-role cardinality | Current assignment API is additive by role ID. | Exactly one active operating role per USER/Tenant. | **EXISTING BUT MODIFY** |
| One PM per Tenant | Not enforced by generic current RBAC. | Required invariant. | **NEW** |
| Direct role union | Current effective permission resolver unions multiple direct Tenant roles. | One operating role per USER/Tenant. | **RETIRE FOR OPERATING USERS** |
| Groups | Current implementation has arbitrary Group CRUD, memberships and Group-to-role assignment; effective permissions union Group-derived roles. | Phase-1 Groups are role-aligned collections for PC/TL/PM/CRM/Executive and inherit exactly the same Tenant role bundle; no separate Group permission grant. | **EXISTING BUT SIMPLIFY/MODIFY** |
| Platform default operational bundles | Approved Audit Core baseline already defines PC/TL/PM/CRM cross-module defaults. | Security seeds those exact Audit Core + DI defaults into each new Tenant. | **EXISTING DESIGN INPUT / ADD TO TARGET** |
| Executive default bundle | Previously open. | Tenant-wide; Audit Core read + normal non-destructive update/write; DI read-only by default. | **CLOSED / ADD TO TARGET** |
| TestUser | Previously exact permission/scope was open. | Existing Clerk TestUser mapped to TestTenant; effective functional bundle equals TestTenant PC bundle. | **CLOSED / ADD TO TARGET** |
| TestTenant | Not previously fixed as a cross-module canonical test tenant. | One canonical Security Tenant ID represented consistently in Security, Audit Core and DI. | **NEW TARGET** |
| Platform/admin roles | Current platform roles exist. | Admin personas retained with fixed Phase-1 scope semantics and authenticate through the same Security human login boundary. | **EXISTING BUT MODIFY** |
| TenantAdmin | Current model does not match the final scope definition. | One Tenant across modules for normal administration; deletion request is global USER operation. | **REDESIGN** |
| ModuleAdmin | Current model does not match the final scope definition. | One module across Tenants, with module-admin/configuration permissions. | **REDESIGN** |
| SuperAdmin | Existing migration grants `platform.super_admin` every active Security permission. | Exactly one Phase-1 SuperAdmin; all ACTIVE permissions across all registered modules automatically. | **EXISTING AND EXTEND** |
| Module permission catalogue | Existing module catalogue, permissions and role templates. | Modules publish permissions; Security exposes module permission discovery; Security remains registry/authority. | **EXISTING AND RETAIN / EXTEND CONTRACT** |
| Role templates | Current templates seed Tenant role objects. | Approved templates/defaults seed Tenant permission bundles for global role classifications. | **EXISTING BUT MODIFY** |
| Tenant role permissions | Current permissions bind to Tenant role IDs. | Bind Tenant + global role_key + permission_key. | **EXISTING BUT MODIFY** |
| Human runtime token | Current `/auth/login` and access-session flows issue Verigence access tokens. | Retain one canonical Security-issued human access JWT after Clerk-backed authentication; remove duplicate/legacy human token paths and keep authorization live in Security. | **EXISTING AND RETAIN WITH MODIFICATION** |
| Security JWKS for human USER token | Current downstream modules trust Security JWT/JWKS. | Retain for human token authentication; downstream permissions are decided synchronously by Security rather than trusted from embedded claims. | **EXISTING AND RETAIN/MODIFY** |
| Security machine/service token | Existing machine/SYSTEM/SERVICE_INTEGRATION token capability exists. | Security is the machine-token issuer; retain/refine into registered ServiceIntegration clients with audience + permission restriction. | **EXISTING AND RETAIN/MODIFY** |
| ServiceIntegration role/model | Existing service actor concepts are present but not yet expressed as the final simple target contract. | Machine-only ServiceIntegration classification, short-lived Security JWT, service-specific audiences/permissions. | **RETAIN/REFINE** |
| Authorization version | Current `user_tenant_authorization_state` supports human token invalidation. | May remain useful for Security-issued human-session revocation/versioning; live authorization remains authoritative. | **RETAIN/REVIEW; NOT AUTHZ SOURCE** |
| Runtime human authorization | Current modules receive permissions embedded in Security human JWT. | Resource server validates Security human JWT; authenticated ServiceIntegration backend calls Security with validated USER identity + Tenant + permission. | **REDESIGN AUTHZ; RETAIN SECURITY HUMAN TOKEN TRUST** |
| Security authorization API | Internal gate logic exists, but not the final ServiceIntegration-authenticated PDP contract. | Add explicit synchronous authorization-check contract. | **NEW/MODIFY** |
| Dealer/Outlet business scope | Audit Core design separates business scope but previously treated Dealer/Outlet terminology separately. | Phase 1 uses one Dealer/Outlet business assignment concept; Security stores none of it. | **RETAIN BOUNDARY / CLARIFY TARGET** |
| Web BFF | No consolidated Web BFF boundary in current Security runtime. | BFF capability is part of Web module; no separate BFF module and no Clerk integration. | **NEW DESIGN BOUNDARY** |
| Audit Core human trust | Current design expects Security-issued JWT + permissions. | Retain Security JWT authentication; replace embedded-permission authority with ServiceIntegration-authenticated synchronous Security AuthZ + Audit Core business scope. | **DEPENDENT DESIGN CHANGE** |
| DI human trust | Current DI expects Security-issued USER JWT. | Retain Security JWT authentication; use ServiceIntegration-authenticated synchronous Security authorization; DI performs no onboarding and has no Clerk integration. | **DEPENDENT DESIGN CHANGE** |
| DI service trust | DI already supports Security service/system identities. | Reuse/refine as ServiceIntegration for Audit Core -> DI. | **EXISTING AND RETAIN/MODIFY** |
| Security audit records | Existing admin/security change/audit structures exist. | Extend to redesigned lifecycle, hard delete, 21-day deletion reference retention, role defaults, role-aligned Groups and ServiceIntegration. | **EXISTING AND RETAIN/MODIFY** |

---

## 36. Migration strategy

No migration is executed by this design document.

After approval, migration should be additive and auditable rather than rewriting historical migrations.

Recommended sequence:

1. freeze this design and the target API/data contracts;
2. introduce new target role-definition and assignment structures;
3. add REJECTED/deletion-request/reactivation lifecycle structures and rules, including global Tenant-independent deletion semantics and 21-day retained deletion-reference policy;
4. bind/configure the single existing Clerk SuperAdmin identity as the one Phase-1 SuperAdmin and extend all-ACTIVE-permission synchronization across registered modules;
5. create/configure canonical TestTenant and bind the existing Clerk TestUser identity to TestTenant with the TestTenant PC bundle;
6. implement TenantAdmin and ModuleAdmin scope semantics/default module-admin bundles;
7. register/refine ServiceIntegration service clients, audience/permission grants and machine-token issuance;
8. add the new ServiceIntegration-authenticated authorization-check service contract;
9. retain/align the Security-only Clerk Backend human authentication facade and one canonical Security human access-token path;
10. migrate active operating-role assignments into one-role-per-USER/Tenant representation after conflict analysis;
11. load the approved PC/TL/PM/CRM platform default bundles from the current approved Audit Core cross-module baseline;
12. add the Executive default rule and seed Tenant-specific permission bundles;
13. simplify Groups to role-aligned collections and remove current additive Group-derived permission behaviour from Phase-1 authorization;
14. retire only duplicate/legacy human token/login contracts after the canonical Security human login/token path is proven; retain `/security/v1/auth/login` as the human authentication facade;
15. keep historical tables/routes disabled or compatibility-only until explicit retention cleanup is approved;
16. align Audit Core and DI designs/contracts after Security behaviour is proven, without introducing Clerk integration into those modules.

### Migration safety checks

Before migrating active role assignments, identify:

- users currently holding multiple direct roles in one Tenant;
- users receiving additional effective roles through existing arbitrary Groups;
- users mixing current platform/admin and Tenant roles;
- Tenants with more than one user who would map to PM;
- permissions currently granted by arbitrary custom Tenant roles that have no mapping to the approved target role catalogue;
- current Group memberships that do not correspond 1:1 with the USER's target operating role;
- existing machine/service identities whose audience/permission grants are broader than the final ServiceIntegration target;
- any existing SuperAdmin assignment that conflicts with the exactly-one Phase-1 rule.

These require explicit remediation rather than automatic guessing.

---

## 37. Phase-1 implementation sequence after design approval

1. **Approve target Security design.**
2. **Produce target Security API/OpenAPI and physical DB design.**
3. **Implement/configure the single SuperAdmin mapping and all-ACTIVE-permission invariant across registered modules.**
4. **Implement/create canonical TestTenant representation in Security and define the cross-module TestTenant ID contract.**
5. **Bind/configure TestUser to TestTenant and TestTenant PC permissions.**
6. **Retain/align Security-only Clerk Backend user creation, email verification and human credential authentication; ensure no direct Web/Mobile/Audit Core/DI Clerk integration.**
7. **Retain/align one canonical Security-issued human access-token path for all human classifications.**
8. **Implement/align global USER onboarding and PENDING/REJECTED/ACTIVE lifecycle.**
9. **Implement status change + global DISABLED deletion-request flow + SuperAdmin-only hard-delete + SuperAdmin-only reactivation + 21-day retained deletion-reference policy.**
10. **Implement global role definitions and one operating-role-per-USER/Tenant assignment model.**
11. **Implement Phase-1 role-aligned Groups as the PC/TL/PM/CRM/Executive user collections tied 1:1 to operating roles.**
12. **Enforce one PM per Tenant and admin/operating exclusivity.**
13. **Implement TenantAdmin one-Tenant/all-modules scope and ModuleAdmin one-module/all-Tenants scope.**
14. **Expose module permission discovery.**
15. **Seed approved PC/TL/PM/CRM defaults and the approved Executive default behavior into Tenant role bundles.**
16. **Implement SuperAdmin Tenant role-bundle review/update flow.**
17. **Implement/refine registered ServiceIntegration service identities, short-lived Security machine-token issuance, audience checks and service-specific permissions.**
18. **Implement synchronous Security authorization-check API authenticated by ServiceIntegration callers using USER identity derived from validated Security human JWTs.**
19. **Implement Web BFF user-administration flows inside the Web module without moving authority or Clerk integration into Web.**
20. **Implement/align Audit Core Dealer/Outlet assignment APIs for PC/TL/PM/CRM associations without Phase-2 cardinality rules.**
21. **Align Audit Core human auth contract to Security human JWT + ServiceIntegration-authenticated synchronous Security AuthZ.**
22. **Align DI direct-human protected access to Security human JWT + ServiceIntegration-authenticated synchronous Security AuthZ; DI remains outside onboarding and Clerk.**
23. **Use ServiceIntegration machine JWTs for Audit Core -> DI.**
24. **Retire duplicate/legacy Security human token/login assumptions while retaining the canonical Security human login/access-token boundary.**
25. **Run migration reconciliation and end-to-end human/machine authorization, lifecycle and cross-module tests before production use.**

---

## 38. Deferred Phase-2 items

The following are deliberately not implemented or overdesigned in Phase 1:

- MFA;
- Dealer/Outlet staffing/cardinality rules;
- number of Dealer/Outlets supported by each PC/TL/PM/CRM;
- exact Dealer/Outlet coverage ratios;
- a separate Dealer-versus-Outlet hierarchy/restriction model;
- distributed human authorization projections;
- custom human OAuth authorization-server implementation beyond the retained Security human authentication/token boundary;
- delegated user-on-behalf-of token exchange;
- arbitrary/custom Groups and Group-specific permission inheritance beyond the Phase-1 role-aligned Groups;
- additional SuperAdmins beyond the single Phase-1 SuperAdmin;
- mTLS for ServiceIntegration unless later required;
- performance caching of Security human allow decisions until measurement proves it necessary.

---

## 39. Open decisions

There are **no remaining Phase-1 design decisions open from the items tracked in this document**.

### Implementation inputs required, not design decisions

- the complete exact Clerk subject for the one Phase-1 SuperAdmin if `user_3I7F…jH9hBMxpN` is redacted;
- the complete exact Clerk subject for TestUser if `user_3I7H…eXFRoeoud` is redacted;
- the canonical TestTenant ID generated/selected during implementation/bootstrap;
- the exact short-lived ServiceIntegration token TTL and credential-rotation interval within the approved machine-token model;
- the concrete configured Security human access-token/session lifetime and revocation behavior must be confirmed from the retained existing implementation rather than invented by this design.

---

## 40. Supersession and alignment rule

After approval, this document is intended to become the Security architecture authority for the topics it covers.

Where existing Security documents/code conflict with this target, the conflict must be resolved through explicit implementation work; historical documents and migrations are not silently rewritten.

Known dependent conflicts requiring later alignment include:

- any Security code or today's implementation changes that removed the canonical human `/security/v1/auth/login` facade on the assumption of direct client Clerk authentication;
- any Web/Mobile/Audit Core/DI design that introduces Clerk SDK/JWT validation outside Security;
- Audit Core's current assumption that human authorization is final from `permissions[]` embedded in the Security-issued JWT rather than a live Security decision;
- DI's current assumption that embedded Security USER JWT permissions are the canonical human authorization contract rather than authenticated identity plus live Security authorization;
- Tenant-owned role objects and additive/group-derived effective-role resolution.

Existing Security-issued human-token capability is retained as the Verigence authentication/session boundary and must be aligned to the single canonical login flow. Existing Security-issued machine/service token capability is separately retained/refined for the `ServiceIntegration` model.

No Audit Core or DI file is modified as part of this Security design document.

---

## 41. Final Phase-1 security invariant

### 41.1 Human path

```text
HUMAN USER
   |
   | signup/login credentials through Verigence API
   | login = identifier + password; no tenantId
   | optional Device/Geo headers do not gate or persist in Phase 1
   v
SECURITY
   |
   +-- only Verigence module integrated with Clerk
   +-- Clerk Backend API creates/verifies human identity and credentials
   +-- Clerk subject -> global Verigence USER
   +-- USER must be ACTIVE for login/protected access
   |
   v
SECURITY-ISSUED HUMAN ACCESS JWT
   |
   +---------------------------+---------------------------+
   |                           |                           |
   v                           v                           v
SECURITY                  AUDIT CORE                     DI
validate Security JWT     validate Security JWT          validate Security JWT
and authorize in-process  extract global USER            extract global USER
   |                           |                           |
   |                           | ServiceIntegration JWT    | ServiceIntegration JWT
   |                           | + USER + Tenant + perm    | + USER + Tenant + perm
   |                           +-------------+-------------+
   |                                         |
   |                                         v
   +-------------------------------> SECURITY AUTHORIZATION
                                      caller service authenticated
                                      USER must be ACTIVE
                                      Tenant context where applicable
                                      operating/admin/test classification
                                      Tenant role bundle seeded from approved default and optionally customized
                                      required permission must be present
                                         |
                                         v
                                      ALLOW / DENY
                                         |
                                         +--> Audit Core additionally checks Dealer/Outlet business scope where applicable
```

Web/Mobile, Web BFF, Audit Core and DI do not call Clerk and do not hold Clerk keys/session tokens.

### 41.2 Machine path

```text
REGISTERED INTERNAL SERVICE
  client identity + confidential credential
       |
       v
VERIGENCE SECURITY
  authenticate registered service
  verify ACTIVE ServiceIntegration principal
  verify requested audience + allowed permissions
       |
       v
short-lived Security-signed machine JWT
  actor_type = SERVICE_INTEGRATION
  aud = target module
       |
       v
TARGET MODULE
  validate Security signature/JWKS
  issuer + expiry + audience + actor type + required service permission
       |
       v
ALLOW / DENY
```

The governing separation is:

> **Clerk stores and verifies human credentials, but Verigence Security is the only Verigence module integrated with Clerk. Web/Mobile authenticates through Security, not directly with Clerk. Security maps the Clerk subject to the global Verigence USER and issues the Verigence human access token. Human login is global: it requires identifier and password, not Tenant context. Optional Device/Geo request context may be sent by clients but is not persisted or used as a Phase-1 login/onboarding gate. Security remains the live functional authorization authority; the human token proves authenticated USER identity but does not replace current role/permission evaluation. Security also authenticates registered machine identities and issues short-lived ServiceIntegration JWTs for module-to-module calls. Role-aligned Groups are the Tenant user collections for the same operating roles and never form a second permission authority. Security starts from approved default role bundles and allows Tenant-specific SuperAdmin changes. The single Phase-1 SuperAdmin has every ACTIVE registered permission. TenantAdmin administers one Tenant across modules for normal administration; global USER deletion is Tenant-independent. ModuleAdmin administers one module across Tenants. TestUser is isolated to TestTenant and follows the TestTenant PC functional bundle. Audit Core decides the single Phase-1 Dealer/Outlet business scope for Audit operations. DI may serve authorized humans directly for approved DI capabilities but owns no human onboarding and has no Clerk integration. The Web BFF is part of the Web module, owns no Security authority and has no Clerk integration.**