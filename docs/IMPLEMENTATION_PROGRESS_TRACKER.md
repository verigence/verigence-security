# Verigence Security — Implementation Progress Tracker

**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + explicitly recorded Phase 4 clarifications  
**Current promoted DEV commit:** `2c43d87c4eb8e52ee50ba1ff60556640d7f4985f`  
**Last updated:** 2026-08-13

## 1. Governing rule

This tracker is operational; approved Security design remains authoritative.

Implementation must not invent missing API shapes, permissions, errors, status semantics, persistence models, event taxonomies, thresholds or provider behavior. Explicit implementation clarifications are recorded separately and versioned rather than silently changing v1.3.

Status values: **DONE**, **PARTIAL**, **PENDING**, **BLOCKED**, **NOT STARTED**.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Security v1.3 design alignment | DONE | Protected by design/static integrity checks |
| GitHub feature/PR/CI promotion model | DONE | Feature → PR → `dev`; Railway uses exact validated merge commit |
| Phase 1 — CI quality gate | DONE | Design/static, compile, Ruff, Mypy, Pytest, build, dependency consistency |
| Phase 2 — Neon DEV | DONE | Approved schema + real PostgreSQL behavior validated |
| Phase 3 — Railway DEV | DONE | Immutable deployment + readiness/liveness/correlation + deployed USER E2E |
| Phase 4 — USER device/session lifecycle | PARTIAL | Internal lifecycle substantially complete; public contracts remain source-gated |
| PENDING device/enrollment persistence | DONE | Creates PENDING state only |
| Device approval persistence | DONE | PENDING→ACTIVE / request→APPROVED |
| Active-device-limit enforcement | DONE | Tenant-configured limit serialized under concurrency |
| USER session refresh internal service | DONE | Complete re-evaluation, token/evidence and approved location movement |
| USER session revoke internal service | DONE | Scoped ACTIVE→REVOKED; existing JWT remains valid to current `exp` |
| Refresh denial evidence | DONE | 4xx policy denials persisted using existing normative reason codes |
| Non-ACTIVE device access gate | DONE | `BLOCKED` and `REVOKED` both deny refresh/new issuance as `DEVICE_NOT_ACTIVE` |
| BLOCKED vs REVOKED business distinction | OPEN | Transition meaning/reversibility/session side-effects are not frozen |
| Public Phase 4 lifecycle routes | BLOCKED BY SOURCE | Approved OpenAPI request/response/security shapes unavailable |
| Persistent cross-replica idempotency | BLOCKED | Approved persistence model unavailable |
| `security_events` taxonomy | OPEN | Free-text schema must not be used to invent event names |
| Security administration APIs | PENDING | Exact endpoint-level `security.*` permission catalogue incomplete |
| SYSTEM/SERVICE_INTEGRATION runtime | PENDING | Machine credentials/tokens pending |
| Tenant operational lifecycle | PENDING | Activation readiness/retention/offboarding execution pending |
| JWKS rotation hardening | PARTIAL | Single-key baseline complete; overlapping rotation pending |
| Clerk live integration | PARTIAL | Adapter exists; live integration not yet proven |
| DI/WPM integration | PENDING | Stable Security token/JWKS contract required |
| UAT/Production readiness | NOT STARTED | Production deployment not approved |

## 3. Phase 4 completed capabilities

| ID | Capability | Status | Evidence / note |
|---|---|---|---|
| P4-001 | PENDING device + enrollment-request persistence | DONE | Real Neon |
| P4-002 | Device approval persistence transition | DONE | Real Neon |
| P4-003 | Active-device-limit serialization | DONE | Tenant/user membership row lock |
| P4-004 | Tenant-configured active-device limit | DONE | Concurrent limit=1 gives one success + `DEVICE_LIMIT_REACHED` |
| P4-005 | One ACTIVE USER session invariant | DONE | PostgreSQL partial unique index |
| P4-006 | USER session revoke | DONE | Scoped transactional ACTIVE→REVOKED |
| P4-007 | Mandatory refresh geo | DONE | Missing geo → `GEO_REQUIRED` |
| P4-008 | Full internal USER refresh | DONE | Tenant/membership/device/geo/location/schedule/network/RBAC/expiry/JWT |
| P4-009 | Approved refresh location movement | DONE | `CLAR-004-001` |
| P4-010 | Refresh session-max preservation | DONE | Original session maximum remains cap |
| P4-011 | Canonical refresh lock order | DONE | Discovery read → device lock → session row lock |
| P4-012 | Successful refresh evidence | DONE | `access_context_evaluations` ALLOW |
| P4-013 | Refresh denial evidence | DONE | 4xx DENY + normative `decision_reason_code` |
| P4-014 | Missing-geo evidence | DONE | `GEO_REQUIRED`, no fabricated session/location/geo context |
| P4-015 | Unapproved-location evidence | DONE | `LOCATION_NOT_ALLOWED`, no session mutation/token |
| P4-016 | Non-ACTIVE device gate | DONE | Both `BLOCKED` and `REVOKED` → `DEVICE_NOT_ACTIVE` |
| P4-017 | Non-ACTIVE-device refresh denial evidence | DONE | Session resolved; no session row lock/update/token after device gate fails |

## 4. Phase evidence

### Phase 1

- CI post-merge `31627855570` — PASS.

### Phase 2

- Neon integration `31630275529` — PASS.
- Detailed evidence: `docs/PHASE_2_NEON_INTEGRATION.md`.

### Phase 3

- Railway runtime/health `31668584825` — PASS.
- Deployed USER E2E `31668795264` — PASS.
- Promotion PR #18.
- Detailed evidence: `docs/PHASE_3_RAILWAY_DEV_VALIDATION.md`.

### Phase 4

#### Increment 1 — persistence/locking foundations

- PR #19.
- Neon `31671140316` — PASS.
- Promoted `7846bb7965fc109ae2570e13b3ef215777388783`.

#### Increment 2 — concurrent active-device limit

- PR #20.
- Neon `31671542390` — 7/7 PASS.
- Security CI `31671820069` — PASS.
- Railway `31671820060` — PASS.
- Promoted `8aaa74b589be618b741507420c6255dda75fa10a`.

#### Increment 3 — refresh geo boundary + USER revoke

- PR #22.
- Neon `31672322586` — 8/8 PASS.
- PR CI `31672417249` — PASS.
- Post-merge CI `31672476255` — PASS.
- Railway `31672476267` — PASS.
- Promoted `26d0a951dfd1c4bd575b1d7c39c538496dc6a9c4`.

#### Increment 4 — full internal refresh + approved location movement

- Clarification `CLAR-004-001` in `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
- PR #24.
- Neon `31673792244` — 9/9 PASS.
- PR CI `31673953419` — PASS.
- Post-merge CI `31674014588` — PASS.
- Railway `31674014592` — PASS.
- Promoted `a42ba20dc74f2c57f5b4444efd044d562c4c76f7`.

#### Refresh concurrency hardening

- PR #25.
- Neon `31674228808` — PASS.
- PR CI `31674296848` — PASS.
- Post-merge CI `31674380079` — PASS.
- Railway `31674380089` — PASS.
- Promoted `83907593ced34a1788306e41942299c1e4a2f7b3`.

#### Increment 5 — refresh denial evidence

- PR #27.
- Neon `31675178770` — PASS.
- PR CI `31675181857` — PASS.
- Post-merge CI `31675264715` — PASS.
- Railway `31675264724` — PASS.
- Promoted `c4c00614af41f83fc13225b676b445366d2d5bbd`.

#### Non-ACTIVE device refresh gate

- PR #29.
- Phase 4 Neon `31675733002` — **12/12 PASS**.
- PR Security CI `31675760014` — PASS.
- Promoted `2c43d87c4eb8e52ee50ba1ff60556640d7f4985f`.
- Post-merge Security CI `31675854749` — PASS.
- Railway `31675854751` — PASS through exact immutable image deployment, readiness, liveness and correlation.

## 5. Approved refresh clarification

`CLAR-004-001` is resolved and implemented:

- refresh always requires fresh geo;
- geo is evaluated only against current effective approved/assigned Tenant locations;
- same approved location refreshes the same ACTIVE session;
- another approved/assigned location may replace the session location only after full policy re-evaluation;
- unapproved geo denies;
- the refreshed token/evidence/session use the location that passed the current evaluation;
- refresh cannot extend the original session maximum-duration end.

## 6. Current blockers / open points

| ID | Point | Status | Rule |
|---|---|---|---|
| OPEN-001 | Persistent idempotency storage | BLOCKED | Do not claim cross-replica replay until an approved persistence model exists |
| OPEN-002 | Invalid correlation-ID rejection response | PARTIAL | Do not propagate invalid caller value |
| OPEN-003 | Exact endpoint-level admin permissions | BLOCKED | Do not invent `security.*` keys |
| OPEN-004 | Cross-module session idle semantics | BLOCKED | Do not invent heartbeat/introspection |
| OPEN-005 | Generic malformed-request normalization | BLOCKED | Do not invent a Security error code |
| OPEN-006 | Authoritative v1.3 OpenAPI unavailable | BLOCKED BY SOURCE | Do not infer public lifecycle route shapes |
| OPEN-007 | Refresh approved-location movement | RESOLVED | `CLAR-004-001` |
| OPEN-008 | `security_events.event_type` taxonomy | OPEN | Do not invent free-text event names |
| OPEN-009 | Device `BLOCKED` vs `REVOKED` business semantics | OPEN | Both are non-ACTIVE; do not invent transition meaning/reversibility/automatic session effects |

Approved OpenAPI SHA-256 remains:

`07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`

Repository history confirms that OpenAPI file was never committed here; it was not deleted or modified in this repository.

## 7. Current execution pointer

**NOW:** continue only deterministic Phase 4 internal behavior supported by approved sources/clarifications.

**CONTRACT DEPENDENCY:** recover or explicitly version a replacement for the approved OpenAPI, then wire exact enrollment/approval/block/revoke/refresh/revoke public routes and run deployed lifecycle E2E.

```text
Phase 1 CI                         DONE
Phase 2 Neon DEV                   DONE
Phase 3 Railway DEV                DONE
Phase 4 device persistence         DONE
Phase 4 device-limit enforcement  DONE
Phase 4 USER revoke                DONE
Phase 4 full USER refresh          DONE
Phase 4 refresh denial evidence    DONE
Phase 4 non-ACTIVE device gate     DONE
BLOCKED vs REVOKED distinction     OPEN-009
Public lifecycle route wiring      BLOCKED BY OPENAPI SOURCE
Persistent idempotency             BLOCKED
Phase 5+                           PENDING / PARTIAL as above
```

## 8. Context-reset recovery

Read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
3. `docs/IMPLEMENTATION_STATUS.md`.
4. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
5. `docs/APPROVED_SOURCE_REFERENCE.md`.
6. v1.3 decision/correlation/lifecycle documents.
7. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
8. Phase evidence documents.
9. Current `dev`, open PRs and CI/Railway runs.

Do not restart from Phase 1 after a context reset. Phases 1–3 are complete and Phase 4 is at the contract boundary described above.
