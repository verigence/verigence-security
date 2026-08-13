# Verigence Security — Implementation Progress Tracker

**Purpose:** Operational view of completed, partial, pending and blocked Security implementation work.  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + explicitly recorded Phase 4 clarifications  
**Current `dev` implementation commit:** `c4c00614af41f83fc13225b676b445366d2d5bbd`  
**Last updated:** 2026-08-13

---

## 1. Mandatory execution rule

This tracker does **not** replace the approved Security design.

Implementation follows `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`:

- approved Security artifacts and explicitly recorded clarifications are authoritative;
- do not reconstruct requirements from chat memory when approved source exists;
- do not invent APIs, fields, permissions, errors, statuses, schema objects, thresholds, event taxonomies or provider behavior;
- do not silently edit original v1.3 normative artifacts;
- unresolved behavior is recorded before code chooses a path;
- code is `DONE` only after applicable tests, review and deployment evidence pass.

Status values: **DONE**, **PARTIAL**, **PENDING**, **BLOCKED**, **NOT STARTED**.

---

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Security v1.3 design alignment | DONE | Initial reviewed baseline protected by design-integrity checks |
| GitHub branch / PR / CI model | DONE | Feature → PR → `dev`; Railway deploy gated by exact-commit Security CI |
| Core USER access path | DONE | Identity → Tenant → device → geo → schedule → network → RBAC → JWT |
| Phase 1 — CI quality gate | DONE | Design/static, compile, Ruff, strict Mypy, Pytest, build and dependency consistency |
| Phase 2 — Neon DEV | DONE | Approved schema deployed and real PostgreSQL behavior validated |
| Phase 3 — Railway DEV | DONE | Immutable deployment, readiness/liveness/correlation and deployed USER E2E |
| Phase 4 — USER device/session lifecycle | PARTIAL | Internal lifecycle through refresh/revoke, approved location movement, concurrency hardening and refresh denial evidence is implemented/validated |
| USER session refresh internal service | DONE | Full re-evaluation, approved-location context move, evidence, token issuance and canonical lock order |
| USER session revoke internal service | DONE | Scoped transactional ACTIVE→REVOKED; issued JWT remains valid only to existing `exp` |
| Device active-limit enforcement | DONE | Concurrent approvals serialized and Tenant-configured limit enforced |
| USER refresh denial evidence | DONE | 4xx refresh denials persisted in `access_context_evaluations` using existing normative reason codes |
| Broader lifecycle denial evidence | PARTIAL | Refresh denials done; remaining device/admin lifecycle denial evidence depends on deterministic lifecycle contracts |
| Public Phase 4 lifecycle routes | BLOCKED BY SOURCE | Exact approved OpenAPI request/response/security shapes unavailable; do not invent them |
| Persistent cross-replica idempotency | BLOCKED | Approved persistence model required |
| Security-event taxonomy | OPEN | `security_events.event_type` is free text; do not invent event names |
| Security administration APIs | PENDING | Exact endpoint permission catalogue incomplete |
| SYSTEM actor runtime | PENDING | Machine credential/token runtime pending |
| SERVICE_INTEGRATION runtime | PENDING | Machine credential/token runtime pending |
| Tenant operational lifecycle | PENDING | Activation readiness, retention execution and offboarding service pending |
| JWKS/key rotation hardening | PARTIAL | Single-key baseline exists; overlapping rotation pending |
| Clerk live integration | PARTIAL | Verification adapter exists; live integration not yet proven |
| DI/WPM integration | PENDING | Must consume stable Security contracts/JWKS |
| UAT / Production readiness | NOT STARTED | Production deployment not approved |

---

## 3. Major completed capabilities

| ID | Capability | Status | Evidence / note |
|---|---|---|---|
| SEC-IMP-001 | FastAPI/Railway service foundation | DONE | Reviewed baseline |
| SEC-IMP-002 | Environment safety for DEV mocks | DONE | UAT/Production fail closed against mock auth |
| SEC-IMP-003 | `X-Correlation-ID` handling | DONE | Preserve/generate/reject/echo + 500 traceability |
| SEC-IMP-004 | Clerk USER identity verification adapter | DONE | Public-key JWT verification boundary |
| SEC-IMP-005 | DEV mock identity | DONE | Cannot inject Tenant roles/permissions |
| SEC-IMP-006 | Security Principal USER validation | DONE | Actor type/status enforced |
| SEC-IMP-007 | Security Access JWT | DONE | Locally validated short-lived JWT |
| SEC-IMP-008 | Single-key JWKS | PARTIAL | Works; overlapping rotation remains |
| SEC-IMP-009 | Canonical permission validation | DONE | Module-prefixed dot notation |
| SEC-IMP-010 | USER geo validation | DONE | Freshness, accuracy, integrity and radius |
| SEC-IMP-011 | Schedule/time evaluation | DONE | Includes overnight windows/overrides |
| SEC-IMP-012 | Provider-neutral network-risk adapter | DONE | Provider call outside DB row-lock window |
| SEC-IMP-013 | PostgreSQL repository foundation | DONE | Neon SQLAlchemy runtime |
| SEC-IMP-014 | Core USER access-session creation/reuse | DONE | Same-context reuse, conflict handling, session max cap |
| SEC-IMP-015 | Successful access-context evidence | DONE | Persisted atomically with successful issuance |
| SEC-IMP-016 | Token/DB atomicity | DONE | Signing failure rolls back session/evidence writes |
| SEC-IMP-017 | Health/readiness | DONE | DB + signing-key fail-closed readiness |
| SEC-IMP-018 | Approved v1.3 PostgreSQL baseline | DONE | Byte-identical initial migration source |
| SEC-IMP-019 | Normative Security error catalogue | DONE | 42/42 aligned |
| SEC-IMP-020 | Neon schema validation | DONE | 27 tables / 7 explicit indexes / 56 FKs / 57 CHECKs |
| SEC-IMP-021 | Railway immutable deployment | DONE | Exact validated GHCR image attached to DEV |
| SEC-IMP-022 | Deployed DEV USER E2E | DONE | Mock identity → real policy/RBAC → JWT against Neon |
| SEC-IMP-023 | PENDING device enrollment persistence | DONE | Device + enrollment request remain PENDING until approval |
| SEC-IMP-024 | Device approval persistence | DONE | PENDING→ACTIVE / PENDING→APPROVED transaction |
| SEC-IMP-025 | Active-device-limit serialization | DONE | Tenant/user membership row lock |
| SEC-IMP-026 | Tenant-configured device limit | DONE | Concurrent limit=1 gives one approval + one `DEVICE_LIMIT_REACHED` |
| SEC-IMP-027 | One ACTIVE USER session invariant | DONE | PostgreSQL partial unique index |
| SEC-IMP-028 | USER session revoke service | DONE | Scoped transactional ACTIVE→REVOKED |
| SEC-IMP-029 | USER refresh mandatory geo | DONE | Missing geo → `GEO_REQUIRED` |
| SEC-IMP-030 | USER refresh full internal re-evaluation | DONE | Tenant/membership/device/geo/location/schedule/network/RBAC/expiry/evidence/JWT |
| SEC-IMP-031 | Approved refresh location transition | DONE | Same approved location stays; different assigned location moves; unapproved geo denies |
| SEC-IMP-032 | Refresh session-max preservation | DONE | Location move cannot extend original session maximum duration |
| SEC-IMP-033 | Refresh canonical lock order | DONE | Discovery read → device lock → session `FOR UPDATE` |
| SEC-IMP-034 | Refresh denial access-context evidence | DONE | 4xx denials persisted after rollback in separate evidence transaction |
| SEC-IMP-035 | Missing-geo denial evidence | DONE | `GEO_REQUIRED` persisted without fabricating session/location/geo context |
| SEC-IMP-036 | Unapproved-location denial evidence | DONE | `LOCATION_NOT_ALLOWED` persisted without session mutation or token issuance |

---

## 4. Phase evidence

### Phase 1 — CI

**DONE** — post-merge CI `31627855570` PASS.

### Phase 2 — Neon DEV

**DONE** — `31630275529` PASS.  
Detailed evidence: `docs/PHASE_2_NEON_INTEGRATION.md`.

### Phase 3 — Railway DEV

**DONE**

- runtime/health: `31668584825` PASS;
- deployed USER E2E: `31668795264` PASS;
- promotion: PR #18.

Detailed evidence: `docs/PHASE_3_RAILWAY_DEV_VALIDATION.md`.

### Phase 4 — USER device/session lifecycle

**PARTIAL — ACTIVE**

#### Increment 1 — persistence / locking foundations

**DONE** — PR #19  
Neon `31671140316` PASS.  
Promoted commit `7846bb7965fc109ae2570e13b3ef215777388783`.

#### Increment 2 — concurrent active-device-limit enforcement

**DONE** — PR #20

- Neon `31671542390`: **7/7 PASS**;
- post-merge Security CI `31671820069`: PASS;
- Railway `31671820060`: PASS;
- promoted commit `8aaa74b589be618b741507420c6255dda75fa10a`.

#### Increment 3 — refresh geo boundary + USER revoke service

**DONE** — PR #22

- Neon `31672322586`: **8/8 PASS**;
- PR Security CI `31672417249`: PASS;
- post-merge Security CI `31672476255`: PASS;
- Railway `31672476267`: PASS;
- promoted commit `26d0a951dfd1c4bd575b1d7c39c538496dc6a9c4`.

#### Increment 4 — approved refresh location transition + full internal refresh

**DONE** — PR #24  
Approved clarification: `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`, `CLAR-004-001`.

Behavior:

- same approved/assigned location → refresh same ACTIVE session;
- different approved/assigned location → re-evaluate all USER gates and move same ACTIVE session to newly approved location;
- geo outside all approved/assigned locations → deny using existing location errors;
- refreshed token/evidence/session use current approved location;
- original session maximum-duration cap remains authoritative.

Validation:

- Neon `31673792244`: **9/9 PASS**;
- PR Security CI `31673953419`: PASS;
- promoted commit `a42ba20dc74f2c57f5b4444efd044d562c4c76f7`;
- post-merge Security CI `31674014588`: PASS;
- Railway `31674014592`: PASS.

#### Increment 4 hardening — canonical refresh lock order

**DONE** — PR #25

Canonical order:

```text
non-locking scoped session read (device discovery)
        ↓
ACTIVE registered-device FOR UPDATE
        ↓
scoped USER access-session FOR UPDATE
        ↓
revalidate session ACTIVE + same device
        ↓
refresh policy evaluation/update
```

Validation:

- Neon `31674228808`: PASS;
- PR Security CI `31674296848`: PASS;
- promoted commit `83907593ced34a1788306e41942299c1e4a2f7b3`;
- post-merge Security CI `31674380079`: PASS;
- Railway `31674380089`: PASS.

#### Increment 5 — USER refresh denial evidence

**DONE** — PR #27

Implementation:

- existing `security.access_context_evaluations` is used for refresh `ALLOW` and `DENY` evidence;
- existing normative Security error code becomes `decision_reason_code` for DENY;
- the failed refresh transaction is rolled back before denial evidence is written in a separate transaction;
- missing geo records `GEO_REQUIRED` without fabricating a session/location/geo context;
- unapproved geo records `LOCATION_NOT_ALLOWED` without updating the session or issuing a token;
- only facts actually resolved are included in evidence;
- 5xx infrastructure/service errors are not mislabeled as policy DENY;
- evidence persistence is best effort and cannot mask the original denial;
- no free-form `security_events.event_type` taxonomy was invented.

Validation:

- final-head Neon `31675178770`: PASS;
- PR #27 Security CI `31675181857`: PASS;
- promoted commit `c4c00614af41f83fc13225b676b445366d2d5bbd`;
- post-merge Security CI `31675264715`: PASS;
- Railway `31675264724`: PASS through exact immutable image deploy, readiness, liveness and correlation.

Detailed Phase 4 evidence: `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.

---

## 5. Remaining Phase 4 work

Internal work still requires source grounding before implementation:

- device BLOCKED/REVOKED lifecycle semantics and associated active-session handling;
- denial evidence for additional device/session lifecycle flows once their transitions are deterministic;
- any required `security_events` records only after an event taxonomy is explicitly frozen.

Source-gated work:

- public device-enrollment route wiring;
- public/admin device approval/block/revoke route wiring;
- public USER refresh/revoke route wiring;
- deployed lifecycle E2E through those public contracts;
- persistent cross-replica `Idempotency-Key` replay.

### Public-contract source gate

`docs/APPROVED_SOURCE_REFERENCE.md` records approved `SECURITY_OPENAPI_v1.3.yaml` SHA-256:

`07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`

Repository history confirms the OpenAPI was never committed to this repository; there is no repository delete/change history for the file. The exact source is also unavailable through the active File Library/context and wider Verigence GitHub code search.

**Rule:** do not infer public request/response/security contracts. Continue deterministic internal implementation from approved decisions/schema/clarifications.

---

## 6. Open / resolved clarifications

| ID | Point | Status | Current rule |
|---|---|---|---|
| OPEN-001 | Persistent idempotency storage | BLOCKED | Do not claim cross-replica replay until persistence model is approved |
| OPEN-002 | Invalid correlation-ID rejection response | PARTIAL | Generate safe server response correlation; never propagate invalid caller value |
| OPEN-003 | Exact endpoint-level `security.*` admin permissions | BLOCKED | Do not invent permission keys |
| OPEN-004 | Cross-module `session_idle_timeout` semantics | BLOCKED | Do not invent heartbeat/introspection dependency |
| OPEN-005 | Generic malformed-request 400 vs framework 422 | BLOCKED | Do not invent new Security error code |
| OPEN-006 | Authoritative v1.3 OpenAPI unavailable | BLOCKED BY SOURCE | Public lifecycle route shapes remain gated |
| OPEN-007 | Refresh to another approved location | **RESOLVED** | `CLAR-004-001`: move same session after complete re-evaluation; unapproved geo denies |
| OPEN-008 | Free-form `security_events.event_type` taxonomy | OPEN | Do not invent event names merely because schema accepts free text |
| OPEN-009 | Device `BLOCKED` vs `REVOKED` transition semantics | OPEN | Do not implement state transitions/session side-effects until approved source or explicit clarification determines the distinction |

---

## 7. Current execution pointer

**NOW:** inspect/resolve deterministic device block/revoke lifecycle semantics and continue only where approved source is sufficient.

**NEXT:** recover/version the authoritative public lifecycle contract; wire exact enrollment/approval/block/revoke/refresh/revoke routes; execute deployed Railway lifecycle E2E.

```text
Phase 1 CI                         DONE
Phase 2 Neon DEV                   DONE
Phase 3 Railway DEV                DONE
Phase 4 Increment 1                DONE
Phase 4 Increment 2                DONE
Phase 4 Increment 3                DONE
Phase 4 Increment 4                DONE — full internal refresh
Phase 4 refresh lock hardening     DONE
Phase 4 Increment 5                DONE — refresh denial evidence
Device block/revoke semantics      OPEN-009 / NOW
Phase 4 public route wiring        BLOCKED BY OPENAPI SOURCE
Phase 4 deployed lifecycle E2E     PENDING PUBLIC ROUTES
Phase 5 Admin APIs                 PENDING
Phase 6/7 Machine actors           PENDING
Phase 8 Operational lifecycle      PENDING
Phase 9 JWKS hardening             PARTIAL
Phase 10 Clerk live integration    PARTIAL
Phase 11 DI/WPM integration        PENDING
Phase 12 UAT/Production            NOT STARTED
```

---

## 8. Progress history

| Date | Reference | Change | Result |
|---|---|---|---|
| 2026-08-12 | `6b4b604f590b918655f695ef315dab457e47d9d9` | Repository initialized | DONE |
| 2026-08-12 | `d11e63f810a3411f0da8dd90b99ea37f5c623582` | Reviewed Security v0.1 baseline | DONE |
| 2026-08-12 | PR #1 / `31627855570` | CI/design-integrity gate | DONE |
| 2026-08-13 | PR #2 / `31630275529` | Neon DEV integration | DONE |
| 2026-08-13 | `31668584825` / `31668795264` | Railway runtime + deployed USER E2E | DONE |
| 2026-08-13 | PR #18 | Phase 3 permanent immutable deploy path | DONE |
| 2026-08-13 | PR #19 / `31671140316` | Phase 4 Increment 1 | DONE |
| 2026-08-13 | PR #20 / `31671542390` | Phase 4 Increment 2 | DONE |
| 2026-08-13 | PR #22 / `31672322586` | Phase 4 Increment 3 | DONE |
| 2026-08-13 | PR #24 / `31673792244` | Phase 4 Increment 4 refresh-context movement | DONE |
| 2026-08-13 | PR #25 / `31674228808` | Refresh lock-order hardening | DONE |
| 2026-08-13 | PR #27 / `31675178770` | Refresh denial access-context evidence | DONE |

---

## 9. Context-reset recovery

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
3. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
4. `docs/IMPLEMENTATION_STATUS.md`.
5. `docs/APPROVED_SOURCE_REFERENCE.md`.
6. `docs/SECURITY_DECISION_REGISTER_v1.3.md`.
7. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`.
8. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
9. Phase evidence documents.
10. Inspect current `dev` HEAD, active feature branch, PR and CI/deployment runs.

Do not reconstruct Security behavior from memory when approved repository sources exist.
