# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security Solution v1.3 + explicit Phase 4 clarifications  
**Current promoted DEV commit:** `36d8618b61fca23b018e3f32f1a15ba06e85f43a`  
**Last updated:** 2026-08-13

## 1. Governing rule

Implementation is grounded in approved Security artifacts, not chat reconstruction.

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`.
2. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.
3. `docs/IMPLEMENTATION_STATUS.md`.
4. `docs/APPROVED_SOURCE_REFERENCE.md`.
5. `docs/SECURITY_DECISION_REGISTER_v1.3.md`.
6. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`.
7. `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.
8. `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.
9. `docs/PHASE_5_SECURITY_ADMINISTRATION.md`.
10. Current `dev`, open PRs and CI/Railway state.

Do not invent a missing API shape, permission, error code, state transition, activation prerequisite, persistence model, event taxonomy, authorization-version rule or Security threshold.

## 2. Current implementation position

### Phase 1 — CI

**DONE.** GitHub Actions enforce design/static integrity, compile, Ruff, strict Mypy, Pytest, package build and dependency consistency.

### Phase 2 — Neon DEV

**DONE.** Approved v1.3 schema is deployed and real PostgreSQL behavior is validated.

### Phase 3 — Railway DEV

**DONE.** Build-once immutable deployment, runtime readiness/liveness/correlation and deployed DEV USER E2E are validated.

### Phase 4 — USER device/session lifecycle

**SUBSTANTIALLY COMPLETE INTERNALLY / CONTRACT BOUNDARY.**

Internal device/session persistence, device-limit concurrency, USER revoke, complete refresh re-evaluation, approved location movement, denial evidence and non-ACTIVE device gating are implemented and validated. Latest accumulated Phase 4 Neon suite `31675733002` is **12/12 PASS**.

Remaining Phase 4 items depend on missing approved public contracts, persistent idempotency design, or the unfrozen business distinction between device `BLOCKED` and `REVOKED`.

### Phase 5 — Security administration foundation

**PARTIAL / CONTRACT BOUNDARY.** Deterministic internal administration is now substantially implemented and deployed.

Completed internal administration:

- Tenant Security Policy configuration;
- Security Retention Policy configuration;
- Tenant locations;
- schedules and schedule windows;
- Security-side USER onboarding records;
- external identity provider-subject mapping;
- Tenant membership;
- employee-location/schedule assignment;
- canonical permission catalogue entries supplied by approved configuration;
- Tenant roles and role-permission grants;
- user-role assignment;
- SEC-032 activation-readiness foundation.

Latest accumulated Phase 5 Neon suite `31681385872`: **11/11 PASS**.

Current promoted commit: `36d8618b61fca23b018e3f32f1a15ba06e85f43a`.  
Post-merge Security CI `31681687084`: PASS.  
Railway `31681687106`: PASS through exact-image deployment, readiness, liveness and correlation.

## 3. Phase 5 readiness rule

SEC-032 readiness is deliberately fail-closed.

The active approved sources currently support these checks:

- ACTIVE Tenant Security Policy / mandatory Tenant Security configuration (SEC-020);
- ACTIVE Security retention policy explicitly required before activation (SEC-037).

`TenantActivationReadinessService` reports PASS/FAIL for those known checks but returns:

- `prerequisite_catalogue_complete=false`;
- `activation_allowed=false`.

Even when all currently-known checks pass, the Tenant remains `CONFIGURING`. Do not implement the `CONFIGURING → ACTIVE` mutation until the complete approved readiness prerequisite catalogue is recovered or explicitly versioned.

## 4. Current blockers / open points

- **OpenAPI unavailable:** approved `SECURITY_OPENAPI_v1.3.yaml` checksum is known, but the source is unavailable. Do not infer public route shapes.
- **Admin permissions:** exact endpoint-level `security.*` permission keys are not frozen. Do not invent them.
- **Activation catalogue:** SEC-032 requires a prerequisite list, but the complete list is not present in active approved sources. Keep activation disabled.
- **Persistent idempotency:** approved cross-replica persistence model is missing.
- **Authorization version:** do not invent automatic bump triggers; internal administration preserves the explicitly supplied approved value.
- **Security event taxonomy:** do not invent free-text event names.
- **Device BLOCKED vs REVOKED:** both are non-ACTIVE for access, but their separate business transition semantics remain unfrozen.
- **Clerk live orchestration:** Security-side USER/external identity persistence exists; invitation/provider API orchestration remains the later Clerk integration phase.

## 5. Current execution pointer

**NOW:** Phase 5 deterministic internal administration foundation is complete enough to stop safely at its contract boundary.

**DO NOT:** enable Tenant activation or expose public Security administration routes by assumption.

**NEXT SAFE PARALLEL PHASE:** begin Phase 6 SYSTEM/SERVICE_INTEGRATION internals only from approved machine-principal schema/decisions. Do not use Phase 6 to bypass unresolved Phase 5 public/activation contracts.

```text
Phase 1 CI                              DONE
Phase 2 Neon DEV                        DONE
Phase 3 Railway DEV                     DONE
Phase 4 internal USER lifecycle         SUBSTANTIALLY DONE / CONTRACT BOUNDARY
Phase 5 policies/retention              DONE
Phase 5 locations/schedules             DONE
Phase 5 membership/RBAC                 DONE
Phase 5 USER onboarding persistence     DONE
Phase 5 readiness foundation            DONE / FAIL-CLOSED
Phase 5 Tenant activation               BLOCKED — incomplete SEC-032 catalogue
Phase 5 public admin APIs               BLOCKED — OpenAPI + admin permissions
Phase 6 machine-actor internals          NEXT SAFE PARALLEL PHASE
```

## 6. Promotion discipline

```text
feature/*
   ↓ real Neon tests + Security CI
  dev
   ↓ exact-commit Security CI
immutable GHCR image
   ↓
Railway DEV
   ↓ readiness + liveness + correlation
```

Every meaningful increment must preserve this promotion sequence and update the tracker/evidence before it is considered complete.

## 7. Context-reset warning

**Do not restart from Phase 1 or Phase 4 after a reset.** Phases 1–3 are complete. Phase 4 and Phase 5 have reached the explicit contract boundaries described above.
