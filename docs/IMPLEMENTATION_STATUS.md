# Verigence Security Implementation Status — Reviewed Baseline + Promoted Increments

This implementation is grounded in **Security Design Source v1.3** plus explicitly recorded implementation clarifications. It does not silently supersede the original v1.3 normative artifacts.

Detailed execution/evidence is maintained in `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`. Initial code-to-design review remains in `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`.

## Core baseline

The promoted implementation includes:

- FastAPI/Railway service foundation;
- DEV/UAT/Production environment safety controls;
- correlation-ID middleware;
- Clerk USER JWT verification adapter and DEV mock identity boundary;
- Security Principal USER validation;
- Security Access JWT/JWKS baseline;
- canonical permissions;
- USER geo/time/network/RBAC evaluation;
- Neon/PostgreSQL repository/session foundation;
- USER access-session creation/reuse;
- evidence persistence and token/DB atomicity;
- health/live and fail-closed readiness;
- exact approved v1.3 PostgreSQL migration source and error catalogue.

## Validated phase milestones

- **Phase 1 CI — DONE.**
- **Phase 2 Neon DEV — DONE.**
- **Phase 3 Railway DEV — DONE.**
- **Phase 4 internal USER device/session lifecycle — substantially DONE; public contracts remain source-gated.**
- **Phase 5 deterministic internal Security administration — substantially DONE; public APIs and Tenant activation remain contract-gated.**

## Phase 4 internal runtime status

Implemented/validated:

- PENDING device enrollment persistence and approval transition;
- concurrent Tenant active-device-limit enforcement;
- one ACTIVE USER session invariant;
- scoped USER session revoke;
- mandatory fresh geo on refresh;
- complete USER refresh policy re-evaluation;
- approved refresh location movement (`CLAR-004-001`);
- original session maximum-duration preservation;
- canonical device→session lock order;
- successful and denied access-context evidence;
- non-ACTIVE device refresh/new-issuance rejection.

Latest accumulated Phase 4 Neon suite: `31675733002` — **12/12 PASS**.  
Promoted Phase 4 runtime evidence: Security CI `31675854749`, Railway `31675854751` — PASS.

## Phase 5 Security administration status

### Tenant policy and retention administration — DONE

Internal administration exists for:

- `tenant_security_policies`;
- `security_retention_policies`.

Security thresholds/TTLs and retention days remain explicit Tenant configuration; no hidden numeric defaults are introduced. Existing runtime policy readers consume administered ACTIVE values directly.

### Tenant location and schedule administration — DONE

Internal administration exists for:

- `tenant_locations`;
- `access_schedules`;
- `access_schedule_windows`.

Normal and overnight schedule definitions written by administration are consumed by the existing runtime schedule reader.

### Tenant membership, employee-location and RBAC administration — DONE

Internal administration exists for:

- `tenant_memberships`;
- `permissions` for explicitly supplied canonical permission keys;
- `roles`;
- `role_permissions`;
- `user_role_assignments`;
- `user_location_assignments`.

Existing runtime authorization readers directly resolve administered membership, assigned location/schedule, role and permission records. The validation uses the already-approved example permission `di.document.upload`; no new production permission key is invented.

Automatic `authorization_version` bump triggers are not invented; administration preserves the explicitly supplied approved value.

### Security-side USER onboarding — DONE internally

Implemented:

- USER `security_principals` persistence;
- `security.users` persistence;
- `external_identities` provider-subject mapping;
- runtime resolution of administered `CLERK` subjects;
- protection against external-identity rebinding to a second USER;
- protection against converting an existing machine principal to USER.

Live Clerk invitation/provider API orchestration is **not** part of this Phase 5 internal foundation and remains a later provider-integration milestone.

### SEC-032 Tenant activation readiness — PARTIAL / FAIL-CLOSED

Implemented internal readiness foundation reports the currently defensible prerequisites:

- ACTIVE Tenant Security Policy / mandatory Security configuration (SEC-020);
- ACTIVE Security retention policy (SEC-037).

The result also states:

- `prerequisite_catalogue_complete=false`;
- `activation_allowed=false`.

A Tenant remains `CONFIGURING` even when all currently-known readiness checks pass. The `CONFIGURING → ACTIVE` mutation is intentionally not implemented until the complete SEC-032 prerequisite catalogue is approved.

## Latest Phase 5 evidence

- Increment 1 PR #31; Railway `31678834647` — PASS.
- Increment 2 PR #32; Railway `31679593399` — PASS.
- Increment 3 PR #33; Railway `31680433590` — PASS.
- Increment 4 PR #34; final-head Neon `31681097935` — 10/10 PASS; Security CI `31681103229` — PASS; promoted `44abea318c3fab5b4ac54c66887e2be1b28cad9c`; Railway `31681204041` — PASS.
- Increment 5 PR #35; final-head Neon `31681528246` — PASS; Security CI `31681577749` — PASS; promoted `36d8618b61fca23b018e3f32f1a15ba06e85f43a`; post-merge Security CI `31681687084` — PASS; Railway `31681687106` — PASS.
- Latest accumulated Phase 5 Neon suite `31681385872` — **11/11 PASS**.

## Intentional remaining gaps / blockers

- authoritative public OpenAPI source is unavailable;
- public Phase 4 lifecycle route wiring therefore remains blocked;
- public Phase 5 administration/readiness/activation route wiring remains blocked;
- exact endpoint-level `security.*` administrator permission catalogue is incomplete;
- complete SEC-032 activation prerequisite catalogue is unavailable;
- Tenant activation mutation remains disabled;
- persistent cross-replica idempotency persistence model is unavailable;
- automatic `authorization_version` mutation rules are not frozen;
- device `BLOCKED` versus `REVOKED` business transition distinction remains unfrozen;
- `security_events.event_type` taxonomy remains unfrozen;
- SYSTEM/SERVICE_INTEGRATION credentials/tokens remain pending;
- retention purge/offboarding execution remains pending;
- overlapping JWKS rotation remains pending;
- live Clerk invitation/onboarding integration remains pending;
- DI/WPM integration and UAT/Production readiness remain pending.

## Current execution direction

Phase 5 deterministic internal administration has reached its safe contract boundary. Do **not** enable Tenant activation or invent public Security administration routes/permissions.

The next safe parallel implementation phase is SYSTEM/SERVICE_INTEGRATION internals, provided it is grounded only in approved machine-principal schema/decisions and is not used to bypass unresolved Phase 5 contracts.
