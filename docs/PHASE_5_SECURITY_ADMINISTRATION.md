# Phase 5 — Security Administration Foundation

**Status:** PARTIAL — Increments 1–4 validated on Neon DEV  
**Approved baseline:** Security Solution v1.3  
**Latest Neon validation run:** `31680743813`

## Objective

Build Security administration from the approved persistence model without inventing public API shapes or endpoint-level `security.*` permission keys that are not frozen by the approved design.

## Increment 1 — Tenant Security Policy and Retention Policy administration

Implemented internal administration for `tenant_security_policies` and `security_retention_policies`. Every Security threshold/TTL and retention duration is explicit; no hidden defaults are introduced. The existing runtime consumes administered ACTIVE policy values unchanged.

Neon `31678680842`: **PASS**.

## Increment 2 — Tenant location and schedule administration

Implemented internal administration for `tenant_locations`, `access_schedules` and `access_schedule_windows`. Exact location/radius/timezone data and normal/overnight windows are persisted and consumed through the existing runtime schedule reader. No implicit window deletion/replacement semantics are invented.

Neon `31679363993`: **6/6 PASS**.

## Increment 3 — Tenant membership, employee-location and RBAC administration

Implemented internal administration for existing USER principals across memberships, canonical permission catalogue rows, Tenant roles, role-permission grants, user-role assignments and user-location/schedule assignments.

The runtime acceptance test proves the existing production authorization repository directly resolves the administered membership, approved location/schedule, Tenant role and approved example permission `di.document.upload`. No separate Phase 5 read model exists.

No automatic `authorization_version` bump policy is invented; the approved value is supplied explicitly.

Neon `31680129517`: **7/7 PASS**.

## Increment 4 — USER onboarding and external identity persistence

Implemented the Security-side portion of employee onboarding:

- `security.security_principals` USER persistence;
- `security.users` persistence;
- `security.external_identities` provider-subject mapping;
- USER updates without silently retyping existing SYSTEM/SERVICE_INTEGRATION principals;
- protection against rebinding an existing external provider subject to another USER.

`UserAdministrationService` intentionally does **not** call Clerk invitation/onboarding APIs. Provider orchestration remains the later Clerk integration phase; Phase 5 owns only the Security authorization-side records.

The real-Neon runtime acceptance test links a unique `CLERK` subject and proves `SecurityRepository.resolve_identity_user()` immediately resolves the administered USER. A conflicting attempt to bind the same subject to another USER is rejected, and a pre-existing SYSTEM principal cannot be converted into a USER through this service.

Neon `31680743813`: **10/10 Phase 5 tests PASS**.

## Deliberately not implemented yet

- public administration routes;
- endpoint-level administrator permission checks;
- live Clerk invitation/API orchestration;
- complete Tenant activation-readiness prerequisite catalogue;
- Tenant activation mutation;
- implicit removal/replacement semantics for assignments or schedule windows;
- automatic `authorization_version` bump rules not explicitly frozen by approved design.

The exact public admin permission catalogue and authoritative public OpenAPI remain source-gated. Phase 5 therefore continues through deterministic internal services first.

## Next safe increment

Implement the SEC-032 activation-readiness foundation as a fail-closed internal evaluator. It may report explicitly frozen prerequisites such as ACTIVE retention policy and mandatory Security configuration, but it must not claim the activation checklist is complete or transition the Tenant to ACTIVE until the full prerequisite catalogue is explicitly approved.
