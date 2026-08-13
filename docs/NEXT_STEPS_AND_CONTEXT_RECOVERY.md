# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + explicit Phase 4 clarifications  
**Current promoted DEV commit:** `2c43d87c4eb8e52ee50ba1ff60556640d7f4985f`  
**Last updated:** 2026-08-13

## 1. Governing rule

Implementation is grounded in approved Security artifacts, not chat reconstruction.

Priority order after a context reset:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
3. `docs/IMPLEMENTATION_STATUS.md`.
4. `docs/APPROVED_SOURCE_REFERENCE.md`.
5. `docs/SECURITY_DECISION_REGISTER_v1.3.md`.
6. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`.
7. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
8. Phase evidence documents and current `dev` code.
9. Current PR/CI/Railway state.

Do not invent a missing API shape, permission, error code, status meaning, persistence model, event taxonomy or Security threshold.

## 2. Approved-source integrity

Approved v1.3 references include:

| Artifact | Approved SHA-256 |
|---|---|
| `SECURITY_OPENAPI_v1.3.yaml` | `07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37` |
| `SECURITY_POSTGRESQL_SCHEMA_v1.3.sql` | `175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d` |
| `SECURITY_DECISION_REGISTER_v1.3.md` | `a05b5e0f04cc63e5d76f54a3a120161aa8ce2172e7c810534c36445e85608070` |
| `SECURITY_CORRELATION_STANDARD_v1.3.md` | `fa0f0886eaf6482e52c00ea612550d0674e5ed7b099bc6e9e2e71a84c1a1e1e0` |
| `SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md` | `0c7c83ae08d4488951ff90e8c95c34eff7220b55da17329dc65699f91288cceb` |

The OpenAPI was never committed to this repository. Repository history contains no delete/change commit for it. Public lifecycle route contracts remain source-gated until the checksum-matching artifact is recovered or a replacement contract is explicitly approved/versioned.

## 3. Current implementation position

### Phase 1 — CI quality gate

**DONE.** GitHub Actions enforce design/static integrity, compile, Ruff, strict Mypy, Pytest, package build and dependency consistency.

### Phase 2 — Neon DEV

**DONE.** Approved v1.3 schema is deployed and real PostgreSQL behavior is validated.

### Phase 3 — Railway DEV

**DONE.** Build-once immutable deployment, runtime readiness/liveness/correlation and deployed DEV USER E2E are validated.

### Phase 4 — USER device/session lifecycle

**PARTIAL — ACTIVE.** Internal lifecycle is substantially complete; public endpoint contracts remain blocked by the missing approved OpenAPI.

Completed Phase 4 behavior:

- PENDING device + enrollment-request persistence;
- PENDING device approval persistence;
- Tenant-configured active-device limit under concurrent approval;
- one ACTIVE USER session per Tenant/user/device PostgreSQL invariant;
- scoped transactional USER session revoke;
- mandatory fresh geo on USER refresh;
- complete internal USER refresh policy re-evaluation;
- approved refresh context movement under `CLAR-004-001`:
  - same approved location → refresh same session;
  - different approved/assigned location → move same session after complete policy re-evaluation;
  - unapproved geo → deny;
- refreshed token/evidence assert the location that passed the current refresh;
- original session maximum-duration cap preserved;
- canonical refresh lock order: session discovery read → device lock → session row lock;
- successful refresh access-context evidence;
- refresh 4xx denial evidence using existing normative Security reason codes;
- both registered-device `BLOCKED` and `REVOKED` states are proven non-ACTIVE and therefore block refresh/new issuance with `DEVICE_NOT_ACTIVE`.

Latest device-gate validation:

- PR #29 Security CI `31675760014`: PASS;
- Phase 4 Neon `31675733002`: **12/12 PASS**;
- promoted commit `2c43d87c4eb8e52ee50ba1ff60556640d7f4985f`;
- post-merge Security CI `31675854749`: PASS;
- Railway `31675854751`: PASS through exact image deployment, readiness, liveness and correlation.

## 4. Current explicit clarifications / blockers

### RESOLVED — USER refresh approved-location movement

`CLAR-004-001` in `docs/PHASE_4_APPROVED_CLARIFICATIONS.md` is authoritative for implementation:

- refresh geo is matched only against current effective approved/assigned locations;
- another approved location may replace the session location only after full policy re-evaluation;
- unapproved geo is rejected.

### BLOCKED — persistent cross-replica idempotency

The approved behavior requires persistence across stateless replicas, but v1.3 contains no approved idempotency persistence model.

### BLOCKED BY SOURCE — public lifecycle routes

Do not invent request/response/security shapes for enrollment, approval/block/revoke, USER refresh or USER revoke until the authoritative OpenAPI is recovered or explicitly replaced/versioned.

### OPEN — device `BLOCKED` versus `REVOKED` business semantics

The schema permits both states and v1.3 requires an ACTIVE device for USER access. What is deterministic and already enforced is:

- `BLOCKED` → not ACTIVE → `DEVICE_NOT_ACTIVE`;
- `REVOKED` → not ACTIVE → `DEVICE_NOT_ACTIVE`.

Do **not** invent the administrative meaning, transition criteria, reversibility or automatic session-side effects that distinguish BLOCKED from REVOKED until approved source/clarification defines them.

### OPEN — `security_events.event_type` taxonomy

The schema accepts free text. Do not invent event names merely because the table permits them. Use `access_context_evaluations` for deterministic ALLOW/DENY policy evidence where appropriate.

### BLOCKED — endpoint-level `security.*` administrator permissions

Permission syntax is frozen; the exact permission key for each admin endpoint is not.

## 5. Current execution pointer

**NOW:** continue only deterministic Phase 4 internal behavior that does not require the missing OpenAPI, an unfrozen device-state distinction or an invented security-event taxonomy.

**NEXT CONTRACT DEPENDENCY:** recover/version `SECURITY_OPENAPI_v1.3.yaml` and then wire exact public lifecycle routes followed by deployed Railway lifecycle E2E.

Do not skip to a later phase merely to work around an unresolved earlier contract.

## 6. Promotion discipline

```text
feature/*
   ↓ real tests + Security CI
  dev
   ↓ exact-commit Security CI gate
immutable GHCR image
   ↓
Railway DEV
   ↓ readiness + liveness + correlation
```

For every meaningful increment:

1. isolate it on a feature branch;
2. run applicable real Neon tests;
3. open a PR to `dev`;
4. require Security CI green;
5. merge only the validated head;
6. verify the exact merge commit through Railway when runtime code changes;
7. update the progress tracker/status/evidence;
8. record any new ambiguity before coding around it.

## 7. Context-reset warning

The old v0.1 roadmap is historical only. **Do not restart from Phase 1.** Phases 1–3 are complete; current work is Phase 4 at the contract boundary described above.
