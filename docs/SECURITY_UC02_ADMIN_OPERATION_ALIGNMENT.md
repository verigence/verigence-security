# Security UC02 — Administrative Operation Alignment

**Status:** UC02 DESIGN ALIGNMENT — OWNER DECISIONS CONFIRMED  
**Date:** 2026-08-21  
**Repository:** `verigence/verigence-security`  
**Branch:** `dev`  
**Related baseline:** `docs/SECURITY_SOLUTION_DESIGN_v2.0.md`, `docs/SECURITY_IMPLEMENTATION_DESIGN_v2.0.md`

> This document is a narrow UC02 alignment amendment. It does not redesign Security v2.0. Where the older documents are ambiguous for Project Onboarding administrative routing, this amendment records the confirmed Phase-1 rule. It must be folded into the next consolidated Security design revision.

## 1. Two backend call modes

Security Phase 1 distinguishes human administrative operations from machine integration operations.

### 1.1 Human administrative operation

Examples include:

- create Tenant/Project identity;
- update Tenant/Project Security metadata;
- activate Tenant/Project;
- hard delete Tenant/Project in the UC02 Phase-1 rollback flow;
- assign/remove operating role;
- other Security control-plane changes.

These operations require the authenticated human administrator identity.

For UC02 the browser calls Audit Core. If Audit Core routes/proxies a Security administrative operation, it MUST forward the same Security-issued human Bearer token supplied by the browser for that request. Audit Core MUST NOT replace the human identity with a `ServiceIntegration` token and MUST NOT mint an impersonated human token.

Security remains responsible for:

1. validating its human JWT;
2. resolving the live global USER;
3. checking live USER status;
4. checking the applicable administrative classification/scope;
5. authorizing the requested Security administrative operation;
6. auditing the human actor and correlation context.

A forwarded human token is still a human request. The intermediate Audit Core hop does not convert it into a machine-admin request.

### 1.2 Machine/integration operation

Registered `ServiceIntegration` credentials/tokens remain the correct mechanism for:

- normal non-administrative module-to-module integration;
- background/service processing;
- calls to `POST /security/v1/authorization/check`;
- other endpoints explicitly designed for machine actors.

A ServiceIntegration token MUST continue to be rejected from human-admin-only Security endpoints.

## 2. UC02 frontend/backend boundary

UC02 does not require a separate Web BFF.

The approved UC02 path is:

```text
Browser
  -> Audit Core
       -> Security admin API with SAME human Bearer token for admin operations
       -> Security authorization/check with ServiceIntegration token for machine authorization checks
       -> DI using the actor mode required by the DI endpoint
```

This keeps the existing Web rule that the browser calls Audit Core, while preserving Security's human-admin-only endpoint rule.

## 3. Tenant/Project association for employees

No new Phase-1 independent `Tenant membership without role` model is introduced for UC02.

The existing Tenant operating-role assignment is the Phase-1 persisted Project association for an employee. A separate Security membership API is not required for UC02.

Consequences:

- the UI may select an approved global Employee before the Role Mapping save;
- the persisted Project association begins when the Tenant operating role is assigned;
- removing the Project assignment removes the Tenant role assignment as applicable;
- removing a Project assignment MUST NOT delete the global USER.

This amendment does not change the existing one-operating-role-per-USER-per-Tenant rule.

## 4. Phase-1 Tenant hard delete for UC02 rollback

The UC02 owner decision brings canonical Tenant hard delete into Phase 1 for SuperAdmin administrative rollback, including a Project that has already been activated.

This is intentionally broader than the earlier assumption that Project deletion would be deferred to Phase 2.

Required Security behaviour:

- human SuperAdmin only;
- ServiceIntegration rejected;
- idempotent/retry-safe semantics;
- Tenant deletion is the **last** step of cross-module Project hard delete, after owning Project data has been removed from DI and Audit Core;
- global USER records are not deleted as a side effect;
- Tenant-scoped operating/admin assignments and Tenant role bundles owned by Security are removed with the Tenant;
- Security records the final administrative delete event/receipt according to the approved platform audit policy.

Target logical API to add to the Security contract:

```text
DELETE /security/v1/platform/tenants/{tenantId}
Authorization: Bearer <Security-issued human SuperAdmin JWT>
```

The exact response body/idempotency header contract must be defined in the Security OpenAPI/implementation design before code is written; it is not invented in this amendment.

## 5. Existing Tenant create contract correction retained

UC02 does not expose a user-entered technical Tenant Code. The Security API must generate its internal Tenant Code/server identifier or otherwise remove that field from the business-facing create request.

The generated value must remain an internal platform concern and must not become a Dealer/Project business field.

## 6. Phase-2 deletion direction

Phase 2 will move from broad rollback-oriented hard delete toward a process-oriented lifecycle/deletion model with maker/checker, retention and controlled disable/inactivate/archive rules where approved.

That Phase-2 direction does not block the Phase-1 UC02 hard-delete requirement.
