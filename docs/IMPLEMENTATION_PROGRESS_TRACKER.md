# Verigence Security — Implementation Progress Tracker

**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + explicitly recorded Phase 4 clarifications  
**Current promoted DEV commit:** `36d8618b61fca23b018e3f32f1a15ba06e85f43a`  
**Last updated:** 2026-08-13

## 1. Governing rule

This tracker is operational; approved Security design remains authoritative.

Implementation must not invent missing API shapes, permissions, errors, status semantics, persistence models, event taxonomies, thresholds, activation prerequisites or provider behavior. Explicit implementation clarifications are recorded separately and versioned rather than silently changing v1.3.

Status values: **DONE**, **PARTIAL**, **PENDING**, **BLOCKED**, **NOT STARTED**.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Security v1.3 design alignment | DONE | Protected by design/static integrity checks |
| GitHub feature/PR/CI promotion model | DONE | Feature → PR → `dev`; Railway uses exact validated merge commit |
| Phase 1 — CI quality gate | DONE | Design/static, compile, Ruff, Mypy, Pytest, build, dependency consistency |
| Phase 2 — Neon DEV | DONE | Approved schema + real PostgreSQL behavior validated |
| Phase 3 — Railway DEV | DONE | Immutable deployment + readiness/liveness/correlation + deployed USER E2E |
| Phase 4 — USER device/session lifecycle | PARTIAL / CONTRACT BOUNDARY | Internal lifecycle substantially complete; public routes/idempotency remain source-gated |
| Phase 5 — Security administration foundation | PARTIAL / CONTRACT BOUNDARY | Internal administration Increments 1–5 implemented, Neon-tested and deployed |
| Tenant Security Policy administration | DONE | Explicit configuration only; runtime consumes administered ACTIVE values |
| Security Retention Policy administration | DONE | Exact Tenant retention days; ACTIVE policy visible to readiness |
| Tenant location administration | DONE | Geo/radius/timezone/address/status persisted and runtime-compatible |
| Schedule/window administration | DONE | Normal + overnight windows persisted and runtime-compatible |
| USER Security-side onboarding | DONE | USER principal/user/external identity persistence; no live Clerk orchestration |
| Tenant membership administration | DONE | Existing USER membership persistence with explicit authorization version |
| Employee-location assignment | DONE | Runtime resolves administered location/schedule assignment |
| Tenant RBAC administration | DONE | Canonical permissions, roles, grants and user-role assignments |
| SEC-032 activation-readiness foundation | PARTIAL / FAIL-CLOSED | Known prerequisites reported PASS/FAIL; full catalogue incomplete, activation disabled |
| Tenant activation mutation | BLOCKED | Complete approved readiness prerequisite catalogue unavailable |
| Public Security administration APIs | BLOCKED BY SOURCE | Exact OpenAPI shapes + endpoint-level `security.*` permission catalogue unavailable |
| Persistent cross-replica idempotency | BLOCKED | Approved persistence model unavailable |
| SYSTEM/SERVICE_INTEGRATION runtime | PENDING | Machine credentials/tokens pending |
| Tenant operational lifecycle | PENDING | Retention execution/offboarding pending |
| JWKS rotation hardening | PARTIAL | Single-key baseline complete; overlapping rotation pending |
| Clerk live integration | PARTIAL | Runtime verification adapter + Security-side identity mapping exist; live provider integration pending |
| DI/WPM integration | PENDING | Stable Security token/JWKS contract required |
| UAT/Production readiness | NOT STARTED | Production deployment not approved |

## 3. Phase 4 summary

Completed internal Phase 4 behavior includes:

- PENDING device/enrollment persistence and approval transition;
- Tenant-configured active-device-limit enforcement under concurrency;
- one-ACTIVE-session PostgreSQL invariant;
- USER session revoke;
- mandatory fresh geo on refresh;
- full USER refresh re-evaluation;
- approved movement of an ACTIVE session to another currently assigned/approved location after full re-evaluation (`CLAR-004-001`);
- canonical refresh lock order;
- successful and denied refresh evidence;
- non-ACTIVE `BLOCKED`/`REVOKED` device refresh/new-issuance rejection.

Latest accumulated Phase 4 Neon suite: `31675733002` — **12/12 PASS**.  
Promoted runtime commit: `2c43d87c4eb8e52ee50ba1ff60556640d7f4985f`.  
Post-merge Security CI `31675854749` — PASS.  
Railway `31675854751` — PASS through exact-image deployment, readiness, liveness and correlation.

Remaining Phase 4 blockers:

- public lifecycle route contracts: missing authoritative OpenAPI;
- persistent cross-replica idempotency: missing approved persistence model;
- business distinction for device `BLOCKED` versus `REVOKED` remains unfrozen.

## 4. Phase 5 completed capabilities

### Increment 1 — Tenant Security Policy + Retention Policy administration

**DONE — PR #31**

Implemented:

- `SecurityAdminRepository`;
- `TenantConfigurationService`;
- explicit Security threshold/TTL configuration with no hidden defaults;
- explicit retention configuration;
- DRAFT/ACTIVE upsert behavior within approved schema;
- runtime compatibility with `SecurityRepository.get_tenant_policy()`.

Evidence:

- initial Neon `31678680842` — PASS;
- final-head Neon `31678747177` — PASS;
- PR Security CI `31678762995` — PASS;
- promoted `16b93636449bd41d9a36b71c063596d66dd505e7`;
- post-merge Security CI `31678834584` — PASS;
- Railway `31678834647` — PASS.

### Increment 2 — Tenant locations + schedules/windows

**DONE — PR #32**

Implemented:

- Tenant location persistence;
- access schedule persistence;
- schedule-window persistence including overnight windows;
- runtime compatibility through existing schedule readers;
- approved PostgreSQL constraint/rollback validation.

Evidence:

- implementation Neon `31679363993` — 6/6 PASS;
- final-head Neon `31679471458` — PASS;
- PR Security CI `31679492087` — PASS;
- promoted `a6383ecb6f4286e5f217b57da084a7f682b3d462`;
- post-merge Security CI `31679593398` — PASS;
- Railway `31679593399` — PASS.

### Increment 3 — Tenant membership + employee-location + RBAC

**DONE — PR #33**

Implemented:

- Tenant membership administration for existing USERs;
- canonical permission catalogue persistence for explicitly supplied permission keys;
- Tenant roles and role-permission grants;
- user-role assignment;
- employee-to-location/schedule assignment;
- direct runtime compatibility with `get_user_context()`, `assigned_locations()` and `effective_user_permissions()`.

The acceptance test uses the already-approved example permission `di.document.upload`; no new production permission key is invented. Automatic `authorization_version` bump semantics are not invented.

Evidence:

- implementation Neon `31680129517` — 7/7 PASS;
- final-head Neon `31680286288` — PASS;
- PR Security CI `31680330019` — PASS;
- promoted `80f4f16653cf1f78724935f20ec96d8377ee2d4a`;
- post-merge Security CI `31680433712` — PASS;
- Railway `31680433590` — PASS.

### Increment 4 — USER onboarding + external identity persistence

**DONE — PR #34**

Implemented the Security-side portion of employee onboarding:

- USER `security_principals` persistence;
- `security.users` persistence;
- `external_identities` provider-subject mapping;
- runtime resolution of administered `CLERK` subjects;
- external identity cannot be rebound to a second USER;
- USER administration cannot retype an existing SYSTEM/SERVICE_INTEGRATION principal.

Live Clerk invitation/API orchestration is deliberately not part of this increment.

Evidence:

- implementation Neon `31680743813` — 10/10 PASS;
- final-head Neon `31681097935` — PASS;
- PR Security CI `31681103229` — PASS;
- promoted `44abea318c3fab5b4ac54c66887e2be1b28cad9c`;
- post-merge Security CI `31681204042` — PASS;
- Railway `31681204041` — PASS.

### Increment 5 — SEC-032 activation-readiness foundation

**DONE AS FOUNDATION / SEC-032 REMAINS PARTIAL — PR #35**

Implemented `TenantActivationReadinessService` as a fail-closed internal evaluator.

Currently defensible prerequisites:

1. `SECURITY_POLICY_ACTIVE` — Security thresholds are mandatory Tenant configuration (SEC-020).
2. `SECURITY_RETENTION_POLICY_ACTIVE` — ACTIVE retention policy explicitly required before activation (SEC-037).

The result deliberately returns:

- per-prerequisite PASS/FAIL;
- `known_prerequisites_pass`;
- `prerequisite_catalogue_complete=false`;
- `activation_allowed=false`.

Even when both currently-known checks pass, the Tenant remains `CONFIGURING`. No activation mutation exists until the complete SEC-032 prerequisite catalogue is approved.

Evidence:

- implementation Neon `31681385872` — **11/11 Phase 5 tests PASS**;
- final-head Neon `31681528246` — PASS;
- PR Security CI `31681577749` — PASS;
- promoted `36d8618b61fca23b018e3f32f1a15ba06e85f43a`;
- post-merge Security CI `31681687084` — PASS;
- Railway `31681687106` — PASS through exact-image deployment, readiness, liveness and correlation.

Detailed Phase 5 evidence: `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.

## 5. Current blockers / open points

| ID | Point | Status | Rule |
|---|---|---|---|
| OPEN-001 | Persistent idempotency storage | BLOCKED | Do not claim cross-replica replay until an approved persistence model exists |
| OPEN-002 | Invalid correlation-ID rejection response | PARTIAL | Do not propagate invalid caller value |
| OPEN-003 | Exact endpoint-level admin permissions | BLOCKED | Do not invent `security.*` keys |
| OPEN-004 | Cross-module session idle semantics | BLOCKED | Do not invent heartbeat/introspection |
| OPEN-005 | Generic malformed-request normalization | BLOCKED | Do not invent a Security error code |
| OPEN-006 | Authoritative v1.3 OpenAPI unavailable | BLOCKED BY SOURCE | Do not infer public lifecycle/admin route shapes |
| OPEN-007 | Refresh approved-location movement | RESOLVED | `CLAR-004-001` |
| OPEN-008 | `security_events.event_type` taxonomy | OPEN | Do not invent free-text event names |
| OPEN-009 | Device `BLOCKED` vs `REVOKED` business semantics | OPEN | Both non-ACTIVE; business transition distinction remains unfrozen |
| OPEN-010 | Complete SEC-032 activation prerequisite catalogue | BLOCKED / CLARIFY | Readiness remains fail-closed and activation disabled until complete catalogue is approved |
| OPEN-011 | Automatic `authorization_version` mutation policy | OPEN | Preserve explicitly supplied value; do not invent bump triggers |

Approved OpenAPI SHA-256 remains:

`07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`

Repository history confirms the OpenAPI file was never committed here; it was not deleted or modified in this repository.

## 6. Current execution pointer

**Phase 5 deterministic internal administration foundation:** substantially complete and deployed.

**NOW:** Phase 5 is at a contract boundary. Do not enable Tenant activation or expose public admin routes until the missing approved SEC-032 prerequisite catalogue, endpoint-level administrator permission catalogue and authoritative OpenAPI contracts are recovered or explicitly versioned.

**NEXT SAFE PARALLEL WORK:** Phase 6 machine-actor internals may begin only from approved SYSTEM/SERVICE_INTEGRATION schema/decisions, without using Phase 6 to bypass the unresolved Phase 5 public/activation contracts.

```text
Phase 1 CI                              DONE
Phase 2 Neon DEV                        DONE
Phase 3 Railway DEV                     DONE
Phase 4 internal USER lifecycle         SUBSTANTIALLY DONE / CONTRACT BOUNDARY
Phase 5 Increment 1 policies            DONE
Phase 5 Increment 2 locations/schedules DONE
Phase 5 Increment 3 membership/RBAC     DONE
Phase 5 Increment 4 USER onboarding     DONE
Phase 5 Increment 5 readiness foundation DONE / FAIL-CLOSED
Phase 5 Tenant activation               BLOCKED BY OPEN-010
Phase 5 public admin APIs               BLOCKED BY OPENAPI + OPEN-003
Phase 6 machine actors                  NEXT SAFE PARALLEL PHASE
UAT/Production                          NOT STARTED
```

## 7. Context-reset recovery

Read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
3. `docs/IMPLEMENTATION_STATUS.md`.
4. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
5. `docs/APPROVED_SOURCE_REFERENCE.md`.
6. v1.3 decision/correlation/lifecycle documents.
7. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
8. `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.
9. `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.
10. Current `dev`, open PRs and CI/Railway runs.

Do not restart from Phase 1 after a context reset. Phases 1–3 are complete; Phase 4 and Phase 5 are at the contract boundaries described above.
