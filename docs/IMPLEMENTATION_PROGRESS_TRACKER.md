# Verigence Security — Implementation Progress Tracker

**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + Phase 4 clarifications + Admin Control Plane v1.4  
**Current promoted DEV commit:** `36d8618b61fca23b018e3f32f1a15ba06e85f43a`  
**Last updated:** 2026-08-13

## 1. Governing rule

This tracker is operational; approved/versioned Security design remains authoritative.

Implementation must not invent missing API shapes, permissions, errors, status semantics, persistence models,
event taxonomies, thresholds, activation prerequisites or provider behavior. Explicit implementation decisions are
recorded and versioned rather than silently changing v1.3.

`docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` is the implementation authority for the new Security Admin
Control Plane, standard administrator roles, groups, module catalogue, module role templates, onboarding,
privileged-access approval and cross-module authorization rules.

Status values: **DONE**, **PARTIAL**, **PENDING**, **BLOCKED**, **NOT STARTED**.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Security v1.3 design alignment | DONE | Protected by design/static integrity checks |
| Security Admin Control Plane v1.4 | DESIGN READY | Versioned Admin/API/RBAC/module/group/onboarding design ready for implementation |
| GitHub feature/PR/CI promotion model | DONE | Feature → PR → `dev`; Railway uses exact validated merge commit |
| Phase 1 — CI quality gate | DONE | Design/static, compile, Ruff, Mypy, Pytest, build, dependency consistency |
| Phase 2 — Neon DEV | DONE | Approved schema + real PostgreSQL behavior validated |
| Phase 3 — Railway DEV | DONE | Immutable deployment + readiness/liveness/correlation + deployed USER E2E |
| Phase 4 — USER device/session lifecycle | PARTIAL / CONTRACT BOUNDARY | Internal lifecycle substantially complete; old v1.3 public routes/idempotency remain source-gated |
| Phase 5 — Security administration foundation | PARTIAL / ACTIVE | Internal foundation complete; v1.4 Admin Control Plane is the current implementation phase |
| Tenant Security Policy administration | DONE | Explicit configuration only; runtime consumes administered ACTIVE values |
| Security Retention Policy administration | DONE | Exact Tenant retention days; ACTIVE policy visible to readiness |
| Tenant location administration | DONE | Geo/radius/timezone/address/status persisted and runtime-compatible |
| Schedule/window administration | DONE | Normal + overnight windows persisted and runtime-compatible |
| USER Security-side onboarding | DONE | USER principal/user/external identity persistence; no live Clerk orchestration |
| Tenant membership administration | DONE | Existing USER membership persistence |
| Employee-location assignment | DONE | Runtime resolves administered location/schedule assignment |
| Tenant RBAC administration | DONE | Canonical permissions, roles, grants and user-role assignments |
| SEC-032 activation-readiness foundation | PARTIAL / FAIL-CLOSED | Known prerequisites reported PASS/FAIL; full catalogue incomplete, activation disabled |
| Tenant activation mutation | BLOCKED | Complete approved readiness prerequisite catalogue unavailable |
| Public Security administration APIs | DESIGN READY / PENDING | v1.4 freezes Admin API surface and endpoint-level `security.*` permission catalogue |
| Groups | DESIGN READY / PENDING | Tenant-scoped, no nested groups, Group → Tenant Role only |
| Module catalogue + role templates | DESIGN READY / PENDING | Module publishes capabilities/templates; Security remains authorization authority |
| Platform Super Admin bootstrap | DESIGN READY / PENDING | Local DEV bootstrap secret + Argon2id + dedicated Platform Admin JWT |
| Team-member invitation/acceptance | DESIGN READY / PENDING | Human acceptance required before membership becomes effective |
| Privileged-access maker-checker | DESIGN READY / PENDING | Privileged role grants require a different authorized approver |
| DI authorization alignment | DESIGN READY / PENDING | Security-JWT model fits; specific DI corrections recorded in v1.4 |
| Persistent cross-replica idempotency | BLOCKED | Approved persistence model unavailable |
| SYSTEM/SERVICE_INTEGRATION runtime | PENDING | Machine credentials/tokens pending after Admin Control Plane priority |
| Tenant operational lifecycle | PENDING | Retention execution/offboarding pending |
| JWKS rotation hardening | PARTIAL | Single-key baseline complete; overlapping rotation pending |
| Clerk live integration | PARTIAL | Runtime verification adapter + Security-side identity mapping exist; live provider integration pending |
| UAT/Production readiness | NOT STARTED | Production deployment not approved |

## 3. Phase 4 summary

Completed internal Phase 4 behavior includes:

- PENDING device/enrollment persistence and approval transition;
- Tenant-configured active-device-limit enforcement under concurrency;
- one-ACTIVE-session PostgreSQL invariant;
- USER session revoke;
- mandatory fresh geo on refresh;
- full USER refresh re-evaluation;
- approved movement of an ACTIVE session to another currently assigned/approved location after full
  re-evaluation (`CLAR-004-001`);
- canonical refresh lock order;
- successful and denied refresh evidence;
- non-ACTIVE `BLOCKED`/`REVOKED` device refresh/new-issuance rejection.

Latest accumulated Phase 4 Neon suite: `31675733002` — **12/12 PASS**.  
Promoted runtime commit: `2c43d87c4eb8e52ee50ba1ff60556640d7f4985f`.  
Post-merge Security CI `31675854749` — PASS.  
Railway `31675854751` — PASS through exact-image deployment, readiness, liveness and correlation.

Remaining Phase 4 blockers:

- legacy/public lifecycle route contracts still depend on the unavailable v1.3 OpenAPI;
- persistent cross-replica idempotency still lacks an approved persistence model;
- business distinction for device `BLOCKED` versus `REVOKED` remains unfrozen.

The new v1.4 Admin Control Plane does not fabricate those older lifecycle contracts.

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
- direct runtime compatibility with `get_user_context()`, `assigned_locations()` and
  `effective_user_permissions()`.

The acceptance test uses the approved example permission `di.document.upload`.

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
2. `SECURITY_RETENTION_POLICY_ACTIVE` — ACTIVE retention policy explicitly required before activation
   (SEC-037).

The result deliberately returns:

- per-prerequisite PASS/FAIL;
- `known_prerequisites_pass`;
- `prerequisite_catalogue_complete=false`;
- `activation_allowed=false`.

Even when both currently-known checks pass, the Tenant remains `CONFIGURING`.

Evidence:

- implementation Neon `31681385872` — **11/11 Phase 5 tests PASS**;
- final-head Neon `31681528246` — PASS;
- PR Security CI `31681577749` — PASS;
- promoted `36d8618b61fca23b018e3f32f1a15ba06e85f43a`;
- post-merge Security CI `31681687084` — PASS;
- Railway `31681687106` — PASS through exact-image deployment, readiness, liveness and correlation.

Detailed Phase 5 evidence: `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.

## 5. Admin Control Plane v1.4 design decisions

`docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` resolves the design blockers that prevented practical
Security administration.

It freezes:

- Platform and Tenant administrator role catalogue;
- endpoint-level `security.*` Admin permission catalogue;
- Platform Super Admin bootstrap model;
- direct Platform Admin Tenant creation (`CONFIGURING` state);
- Tenant Groups and inheritance rules;
- module catalogue and module role-template model;
- permission namespace ownership;
- Tenant role/template materialization rules;
- human acceptance for team-member onboarding;
- maker-checker for privileged Tenant administration roles;
- RBAC `authorization_version` mutation semantics;
- Admin API route plan;
- v1.4 database extension plan;
- DI integration/alignment work;
- required deployed Security → DI E2E.

The literal temporary DEV bootstrap password is deliberately not stored in Git/documentation. It remains an
operator-managed deployment secret.

## 6. Current blockers / open points

| ID | Point | Status | Rule |
|---|---|---|---|
| OPEN-001 | Persistent idempotency storage | BLOCKED | Do not claim cross-replica replay until an approved persistence model exists |
| OPEN-002 | Invalid correlation-ID rejection response | PARTIAL | Do not propagate invalid caller value |
| OPEN-003 | Exact endpoint-level Admin permissions | RESOLVED BY v1.4 | Use the `security.*` catalogue in `SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` |
| OPEN-004 | Cross-module session idle semantics | BLOCKED | Do not invent heartbeat/introspection |
| OPEN-005 | Generic malformed-request normalization | BLOCKED | Do not invent a Security error code |
| OPEN-006 | Authoritative v1.3 OpenAPI unavailable | PARTIAL BLOCKER | Still blocks old v1.3 lifecycle routes; no longer blocks the new versioned v1.4 Admin Control Plane |
| OPEN-007 | Refresh approved-location movement | RESOLVED | `CLAR-004-001` |
| OPEN-008 | `security_events.event_type` taxonomy | OPEN | v1.4 Admin mutations use a structured Admin change record rather than inventing free-text event names |
| OPEN-009 | Device `BLOCKED` vs `REVOKED` business semantics | OPEN | Both non-ACTIVE; mutation distinction remains unfrozen |
| OPEN-010 | Complete SEC-032 activation prerequisite catalogue | BLOCKED / CLARIFY | Readiness remains fail-closed and activation disabled |
| OPEN-011 | RBAC `authorization_version` mutation policy | RESOLVED BY v1.4 | Increment on changes that affect effective RBAC permissions as specified by v1.4 |

Approved legacy v1.3 OpenAPI SHA-256 remains:

`07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`

Repository history confirms the v1.3 OpenAPI file was never committed here; it was not deleted or modified in
this repository.

## 7. Current execution pointer

**NOW:** implement Security Admin Control Plane v1.4 in the sequence defined by
`docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`.

The next implementation increment is:

```text
v1.4 Increment A
  -> migration 0002_security_admin_control_plane_v1.4.sql
  -> standard security.* permission catalogue
  -> standard Platform/Tenant Admin roles
  -> module/group/invitation/approval/admin-audit persistence
  -> real Neon validation
```

Then continue:

```text
Increment B  Platform Super Admin bootstrap/login + direct Tenant creation
Increment C  Module catalogue API + initial DI synchronization
Increment D  Groups + effective RBAC
Increment E  Tenant role Admin APIs
Increment F  Team-member invitation + human acceptance
Increment G  Privileged maker-checker
Increment H  Expose existing policy/location/schedule/device Admin services
Increment I  DI authorization alignment
Increment J  Deployed Security -> DI E2E
```

Do **not** move to Phase 6 as the primary workstream until the practical Admin Control Plane is implemented and
validated.

```text
Phase 1 CI                              DONE
Phase 2 Neon DEV                        DONE
Phase 3 Railway DEV                     DONE
Phase 4 internal USER lifecycle         SUBSTANTIALLY DONE / LEGACY CONTRACT BOUNDARY
Phase 5 internal admin foundation       DONE / DEPLOYED
Admin Control Plane v1.4 design         READY
Admin Control Plane v1.4 implementation NOW
Tenant activation                       BLOCKED BY OPEN-010
Phase 6 machine actors                  AFTER ADMIN CONTROL PLANE PRIORITY
UAT/Production                          NOT STARTED
```

## 8. Context-reset recovery

Read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`.
3. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
4. `docs/IMPLEMENTATION_STATUS.md`.
5. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
6. `docs/APPROVED_SOURCE_REFERENCE.md`.
7. v1.3 decision/correlation/lifecycle documents.
8. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
9. `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.
10. `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.
11. Current Security `dev`, current DI `dev`, open PRs and CI/Railway runs.

Do not reconstruct the Admin Control Plane from chat history after v1.4 is merged.
