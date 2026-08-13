# Phase 5 — Security Administration Foundation

**Status:** PARTIAL — Increments 1–5 validated on Neon DEV  
**Approved baseline:** Security Solution v1.3  
**Latest Neon validation run:** `31681385872`

## Objective

Build Security administration from the approved persistence model without inventing public API shapes, endpoint-level `security.*` permission keys, or activation prerequisites that are not frozen by approved design.

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

- USER `security_principals` persistence;
- `security.users` persistence;
- `external_identities` provider-subject mapping;
- protection against retyping existing machine principals;
- protection against rebinding an external provider subject to a second USER.

Live Clerk invitation/API orchestration remains the later Clerk integration phase. The runtime acceptance test proves an administered `CLERK` subject resolves through the existing `SecurityRepository.resolve_identity_user()` path.

Final-head Neon `31681097935`: **10/10 PASS**.  
PR #34 Security CI `31681103229`: **PASS**.  
Promoted commit: `44abea318c3fab5b4ac54c66887e2be1b28cad9c`.  
Post-merge Security CI `31681204042`: **PASS**.  
Railway `31681204041`: **PASS** through exact-image deployment, readiness, liveness and correlation.

## Increment 5 — SEC-032 activation-readiness foundation

Implemented `TenantActivationReadinessService` as a fail-closed internal evaluator.

The active approved sources currently support these readiness facts:

1. Tenant Security thresholds are mandatory Tenant configuration rather than code defaults; the evaluator therefore reports whether an ACTIVE Tenant Security Policy exists.
2. SEC-037 explicitly requires an ACTIVE Security retention policy before Tenant activation.

The evaluator returns each known prerequisite as PASS/FAIL and also returns:

- `known_prerequisites_pass`;
- `prerequisite_catalogue_complete=false`;
- `activation_allowed=false`.

Even when both known prerequisites pass, the evaluator does **not** mutate the Tenant to ACTIVE because the complete SEC-032 prerequisite catalogue is not present in the active approved sources. This preserves fail-closed activation semantics without pretending the design is complete.

Neon `31681385872`: **11/11 Phase 5 tests PASS**. The test verifies the Tenant remains `CONFIGURING` after all currently-known prerequisites pass.

## Deliberately not implemented yet

- public administration routes;
- endpoint-level administrator permission checks;
- live Clerk invitation/API orchestration;
- complete SEC-032 prerequisite catalogue;
- Tenant activation mutation;
- implicit removal/replacement semantics for assignments or schedule windows;
- automatic `authorization_version` bump rules not explicitly frozen by approved design.

The exact public admin permission catalogue and authoritative public OpenAPI remain source-gated.

## Current boundary

Phase 5 now has deterministic internal administration for Tenant policies, retention, locations, schedules, USER onboarding, membership, employee-location assignment and RBAC, plus a fail-closed SEC-032 readiness foundation.

The next step that can change a Tenant to `ACTIVE`, or expose these operations as public administrator APIs, must wait for the missing approved contract details rather than inventing them.
