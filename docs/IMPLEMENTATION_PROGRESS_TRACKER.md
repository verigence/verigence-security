# Verigence Security — Implementation Progress Tracker

**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + Phase 4 clarifications + Admin Control Plane v1.4  
**Current promoted DEV commit:** `44a3a868d82d03cdb4bca9250a6ce14769d9db8a`  
**Last updated:** 2026-08-13

## 1. Governing rule

This tracker is operational; approved/versioned Security design remains authoritative.

Implementation must not invent missing API shapes, permissions, errors, status semantics, persistence models,
event taxonomies, thresholds, activation prerequisites or provider behavior. Explicit implementation decisions are
recorded and versioned rather than silently changing v1.3.

The following are implementation authorities for the new control-plane scope:

- `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
- `docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md`;
- `docs/SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md`.

Status values: **DONE**, **PARTIAL**, **PENDING**, **BLOCKED**, **NOT STARTED**.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Security v1.3 design alignment | DONE | Protected by design/static integrity checks |
| Security Admin Control Plane v1.4 | PARTIAL / ACTIVE | Increments A and B DONE/deployed; Increment C Module Catalogue API + DI sync is next |
| GitHub feature/PR/CI promotion model | DONE | Feature → PR → `dev`; Railway uses exact validated merge commit |
| Phase 1 — CI quality gate | DONE | Design/static, compile, Ruff, Mypy, Pytest, build, dependency consistency |
| Phase 2 — Neon DEV | DONE | Approved schema + real PostgreSQL behavior validated |
| Phase 3 — Railway DEV | DONE | Immutable deployment + readiness/liveness/correlation + deployed USER E2E |
| Phase 4 — USER device/session lifecycle | PARTIAL / CONTRACT BOUNDARY | Internal lifecycle substantially complete; old v1.3 public routes/idempotency remain source-gated |
| Phase 5 — Security administration foundation | PARTIAL / ACTIVE | Internal foundation complete; Admin Control Plane v1.4 implementation in progress |
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
| Admin Control Plane v1.4 persistence | DONE | Migration `0002`, 19 new tables, 44 Admin permissions, Platform roles and 24 control definitions promoted/deployed |
| Security Control Registry persistence | DONE | Definitions, Platform settings and Tenant override persistence exist; runtime evaluation/API remains pending |
| Public Security administration APIs | PARTIAL / ACTIVE | Platform Super Admin authentication and direct Tenant APIs DONE; remaining Tenant/module/group/onboarding APIs pending |
| Groups | PARTIAL | Persistence and Tenant-safe constraints DONE; HTTP APIs/effective Group RBAC pending |
| Module catalogue + role templates | PARTIAL / NEXT | Persistence DONE; catalogue API + DI synchronization is Increment C |
| Platform Super Admin bootstrap | DONE | Idempotent deployment bootstrap, Argon2id credential, dedicated Admin JWT and password-change gate deployed |
| Direct Platform Tenant administration | DONE | Create/list/get/update APIs deployed; new Tenant starts CONFIGURING and standard Tenant Admin roles seed transactionally |
| Self-onboarding | PARTIAL | Hash-only Tenant token/request persistence DONE; Tenant token may be configured during Tenant creation; submission/admin approval APIs pending |
| Team-member invitation/acceptance | PARTIAL | Invitation persistence DONE; runtime acceptance APIs pending |
| Privileged-access maker-checker | PARTIAL | Request persistence/constraints DONE; execution APIs pending |
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

## 5. Security Admin Control Plane v1.4 implementation

### Increment A — schema and standard catalogues

**DONE — PR #39**

Implemented and promoted:

- additive `migrations/0002_security_admin_control_plane_v1.4.sql`;
- 19 new control-plane persistence tables;
- exact 44-key `security.*` Admin permission catalogue;
- four Platform roles and exact permission bundles;
- drift-safe eight-role Tenant Admin seeding;
- module and role-template persistence;
- Groups and Group-role persistence with cross-Tenant FK protection;
- invitation and privileged-access request persistence;
- structured Admin change/audit persistence;
- Security Control Registry definitions, Platform settings and Tenant overrides;
- 12 configurable controls and 12 non-disableable core controls;
- hash-only Tenant self-onboarding token settings;
- self-onboarding request persistence and duplicate-open/effective protection.

Evidence:

```text
Initial real-Neon validation:    31690567354 — 15/15 PASS
Final-head real-Neon validation: 31691819076 — PASS
PR Security CI:                  31691822076 — PASS
Promoted DEV commit:             b1c4d60267ccffae4a6a64a3ec87099c13e193e7
Post-merge Security CI:          31691980302 — PASS
Railway DEV deployment/smoke:    31691980334 — PASS
```

The Neon workflow verifies the immutable v1.3 migration digest before applying `0002` with
`ON_ERROR_STOP=1`.

Detailed evidence: `docs/ADMIN_CONTROL_PLANE_INCREMENT_A_VALIDATION.md`.

### Increment B — Platform Super Admin + direct Tenant administration

**DONE — PR #41**

Implemented and promoted:

- idempotent deployment-controlled Platform Super Admin bootstrap;
- bootstrap login/password supplied only from deployment configuration/secrets;
- Argon2id hash-only local Platform credential persistence;
- restart does not reset an existing Super Admin password;
- mandatory first-password-change gate (`must_change_password=true`);
- dedicated Platform Admin JWT with audience `verigence-security-admin` and no Tenant/access-session context;
- Platform login, password-change and `/me` APIs;
- direct Tenant create/list/get/update APIs protected by frozen `security.tenant.*` permissions;
- new Tenant starts `CONFIGURING`;
- eight reserved Tenant Admin roles and exact v1.4 permission bundles seed in the same Tenant provisioning transaction;
- optional Tenant self-onboarding token is Argon2id-hashed at Tenant creation and never stored in plaintext;
- structured Admin audit records for bootstrap, password and Tenant mutations;
- Tenant activation remains unavailable/fail-closed under OPEN-010.

Evidence:

```text
Final feature head:              6bff9941417d490856f80d18aa8a2d20455e2ffd
Final-head real-Neon validation: 31694765879 — 16/16 PASS
PR Security CI:                  31694771302 — PASS
Promoted DEV commit:             44a3a868d82d03cdb4bca9250a6ce14769d9db8a
Post-merge Security CI:          31694931046 — PASS
Railway DEV deployment/smoke:    31694931027 — PASS
```

Detailed evidence: `docs/ADMIN_CONTROL_PLANE_INCREMENT_B_VALIDATION.md`.

### Remaining Admin Control Plane increments

```text
Increment C  Module catalogue API + initial DI synchronization
Increment D  Groups + effective RBAC
Increment E  Tenant role Admin APIs
Increment F  Team-member invitation + human acceptance + self-onboarding approval
Increment G  Privileged maker-checker
Increment H  Security Control Registry runtime/API + policy/location/schedule/device Admin APIs
Increment I  DI authorization alignment
Increment J  Deployed Security -> DI E2E
```

## 6. Current blockers / open points

| ID | Point | Status | Rule |
|---|---|---|---|
| OPEN-001 | Persistent idempotency storage | BLOCKED | Do not claim cross-replica replay until an approved persistence model exists |
| OPEN-002 | Invalid correlation-ID rejection response | PARTIAL | Do not propagate invalid caller value |
| OPEN-003 | Exact endpoint-level Admin permissions | RESOLVED BY v1.4 | Use the `security.*` catalogue in `SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` |
| OPEN-004 | Cross-module session idle semantics | BLOCKED | Do not invent heartbeat/introspection |
| OPEN-005 | Generic malformed-request normalization | BLOCKED | Do not invent a Security error code |
| OPEN-006 | Authoritative v1.3 OpenAPI unavailable | PARTIAL BLOCKER | Still blocks old v1.3 lifecycle routes; does not block the new v1.4 Admin Control Plane |
| OPEN-007 | Refresh approved-location movement | RESOLVED | `CLAR-004-001` |
| OPEN-008 | `security_events.event_type` taxonomy | OPEN | v1.4 Admin mutations use structured `admin_change_records` instead of inventing free-text event names |
| OPEN-009 | Device `BLOCKED` vs `REVOKED` business semantics | OPEN | Both non-ACTIVE; mutation distinction remains unfrozen |
| OPEN-010 | Complete SEC-032 activation prerequisite catalogue | BLOCKED / CLARIFY | Readiness remains fail-closed and activation disabled |
| OPEN-011 | RBAC `authorization_version` mutation policy | RESOLVED BY v1.4 | Increment on changes affecting effective RBAC permissions as specified by v1.4 |

Approved legacy v1.3 OpenAPI SHA-256 remains:

`07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`

## 7. Current execution pointer

**NOW:** Admin Control Plane v1.4 **Increment C — Module Catalogue API + initial DI synchronization**.

Implement from promoted `dev@44a3a868d82d03cdb4bca9250a6ce14769d9db8a`:

```text
Module catalogue administration
  -> PUT /security/v1/platform/modules/{moduleKey}/catalog
  -> GET module catalogue/list/detail
  -> Platform permission security.module.manage/read
  -> module namespace ownership validation
  -> canonical permission key validation
  -> catalogue version persistence
  -> ACTIVE / DEPRECATED / RETIRED lifecycle handling without unsafe deletion

Module role templates
  -> create/update versioned module templates from the submitted catalogue
  -> every template permission must belong to the same module namespace
  -> later template changes do not silently alter existing Tenant roles

Initial DI synchronization
  -> source permission keys/templates from the reviewed DI repository
  -> register the current DI catalogue through the same Security catalogue service/API model
  -> validate registered DI permissions/templates on real Neon
```

**NEXT after Increment C:** Increment D — Groups + effective RBAC.

Do **not** move to Phase 6 as the primary workstream until the practical Admin Control Plane is implemented and
validated.

```text
Phase 1 CI                              DONE
Phase 2 Neon DEV                        DONE
Phase 3 Railway DEV                     DONE
Phase 4 internal USER lifecycle         SUBSTANTIALLY DONE / LEGACY CONTRACT BOUNDARY
Phase 5 internal admin foundation       DONE / DEPLOYED
Admin Control Plane v1.4 design         DONE / VERSIONED
Admin Control Plane Increment A         DONE / DEPLOYED
Admin Control Plane Increment B         DONE / DEPLOYED
Admin Control Plane Increment C         NOW
Tenant activation                       BLOCKED BY OPEN-010
Phase 6 machine actors                  AFTER ADMIN CONTROL PLANE PRIORITY
UAT/Production                          NOT STARTED
```

## 8. Context-reset recovery

Read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`.
3. `docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md`.
4. `docs/SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md`.
5. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
6. `docs/ADMIN_CONTROL_PLANE_INCREMENT_A_VALIDATION.md`.
7. `docs/ADMIN_CONTROL_PLANE_INCREMENT_B_VALIDATION.md`.
8. `docs/IMPLEMENTATION_STATUS.md`.
9. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
10. `docs/APPROVED_SOURCE_REFERENCE.md`.
11. v1.3 decision/correlation/lifecycle documents.
12. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
13. `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.
14. `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.
15. Current Security `dev`, current DI `dev`, open PRs and CI/Railway runs.

Do not reconstruct Security behavior from chat history when the repository contains the approved/recovery source.
