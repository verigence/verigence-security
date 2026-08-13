# Verigence Security Implementation Status — v0.1 Baseline + Promoted Increments

This implementation is grounded in **Security Design Source v1.3** plus explicitly recorded implementation clarifications. It does not silently supersede or rewrite the original v1.3 normative artifacts.

Detailed execution/evidence is maintained in `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`. The initial code-to-design review remains in `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`.

## Reviewed baseline capabilities

The v0.1 baseline provides:

- FastAPI/Railway service foundation;
- environment safety for DEV mock authentication/network adapters;
- `X-Correlation-ID` handling for normal, Security-error and unexpected-500 responses;
- Clerk USER JWT verification adapter and DEV mock identity boundary;
- Security Principal USER validation;
- Security RSA Access JWT issue/verify and single-key JWKS;
- canonical permission validation;
- geo freshness/accuracy/integrity/radius checks;
- access schedule/time evaluation including overnight windows;
- provider-neutral network-risk evaluation outside the DB row-lock window;
- Neon/PostgreSQL repository/session foundation;
- Tenant membership, ACTIVE device, location assignment, schedule and RBAC resolution;
- core USER access-session create/reuse with same-context reuse and conflict handling;
- session maximum-duration preservation;
- successful access-context evidence;
- token/DB atomicity;
- DEV mock-auth bootstrap;
- health/live and fail-closed health/ready;
- exact approved v1.3 PostgreSQL migration source;
- exact 42-code/status Security error catalogue.

## Validated milestones after v0.1

- **Phase 1 CI — DONE:** design/static integrity, compile, Ruff, strict Mypy, Pytest, package build and dependency consistency.
- **Phase 2 Neon DEV — DONE:** approved Security schema deployed/validated; real PostgreSQL locking and constraints exercised.
- **Phase 3 Railway DEV — DONE:** build-once immutable deployment, runtime configuration, readiness/liveness/correlation and deployed DEV USER E2E.
- **Phase 4 Increment 1 — DONE:** PENDING device/enrollment persistence, approval persistence, device-limit serialization primitives, scoped session-revoke persistence and one-ACTIVE-session PostgreSQL invariant.
- **Phase 4 Increment 2 — DONE:** Tenant-configured `max_active_devices_per_user` enforced under concurrent approvals.
- **Phase 4 Increment 3 — DONE:** missing USER refresh geo returns normative `GEO_REQUIRED`; scoped USER session revoke is transactional and preserves existing JWT validity only until its existing `exp`.
- **Phase 4 Increment 4 — DONE internally:** full USER refresh policy re-evaluation and approved location-context movement are implemented under `CLAR-004-001`.
- **Phase 4 refresh concurrency hardening — DONE:** refresh uses canonical device→session row-lock order consistent with create/reuse.
- **Phase 4 Increment 5 — DONE:** USER refresh 4xx denials persist deterministic access-context evidence using existing normative Security reason codes without inventing `security_events` event names.

### Phase 4 refresh behavior now implemented

For an existing ACTIVE USER access session:

1. a new geo sample is mandatory;
2. Tenant, membership and device must remain valid/ACTIVE;
3. geo freshness, accuracy and integrity are re-evaluated;
4. geo is matched only against currently ACTIVE/effective assigned Tenant locations;
5. the matched location's schedule/time/override is re-evaluated;
6. network policy and effective RBAC are re-evaluated;
7. token/session expiry remains bounded by token TTL, geo revalidation interval, matched schedule and the original session maximum-duration end;
8. same approved location refreshes the same session;
9. a different approved/assigned location moves the same ACTIVE session context to that new location after all checks pass;
10. geo outside all approved/assigned locations is denied without mutating session context;
11. successful evidence and refreshed JWT use the newly matched approved location;
12. refresh lock ordering is discovery read → ACTIVE device lock → scoped session `FOR UPDATE` → revalidation;
13. 4xx refresh denials are rolled back first and then recorded in a separate `access_context_evaluations` DENY transaction;
14. the existing normative Security error code is used as the denial `decision_reason_code`;
15. missing geo records `GEO_REQUIRED` without fabricating session/location/geo values;
16. unapproved geo records `LOCATION_NOT_ALLOWED` without session update or token issuance;
17. 5xx infrastructure/service failures are not mislabeled as access-policy denials;
18. evidence-storage failure cannot mask the original Security denial.

Approved clarification source: `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.

## Latest Phase 4 evidence

- Increment 4 real Neon `31673792244`: **9/9 PASS**.
- PR #24 Security CI `31673953419`: PASS.
- Increment 4 post-merge Security CI `31674014588`: PASS.
- Increment 4 Railway `31674014592`: PASS.
- Lock-order hardening Neon `31674228808`: PASS.
- PR #25 Security CI `31674296848`: PASS.
- Lock-order post-merge Security CI `31674380079`: PASS.
- Lock-order Railway `31674380089`: PASS.
- Increment 5 final-head Neon `31675178770`: PASS.
- PR #27 Security CI `31675181857`: PASS.
- Current promoted `dev` commit `c4c00614af41f83fc13225b676b445366d2d5bbd`.
- Current post-merge Security CI `31675264715`: PASS.
- Current Railway immutable deploy/readiness/liveness/correlation `31675264724`: PASS.

## Not yet implemented / not yet complete

The following remain intentional implementation gaps rather than removed scope:

- persistent idempotency storage/replay across stateless replicas;
- exact public device enrollment/approval/block/revoke route contracts and wiring;
- exact public USER session refresh/revoke route contracts and wiring;
- deployed Phase 4 lifecycle E2E through those public routes;
- device BLOCKED/REVOKED transition semantics and their active-session side effects until approved source/clarification is deterministic;
- denial evidence for remaining device/admin lifecycle flows after their transitions are frozen;
- any `security_events.event_type` taxonomy that has not been explicitly frozen;
- machine-principal credentials and machine access-token endpoint;
- SYSTEM/SERVICE_INTEGRATION administration/runtime;
- Tenant activation-readiness application service;
- retention purge execution;
- Tenant offboarding application service/endpoints;
- complete Security administration APIs;
- endpoint-level `security.*` administrator permission catalogue;
- overlapping JWKS key rotation;
- production network-risk provider adapter;
- Clerk invitation/onboarding calls and live Clerk integration test.

## Open / resolved design and source points

1. **Persistent idempotency — BLOCKED:** v1.3 requires stateless-replica replay semantics but has no approved persistent idempotency model.
2. **Invalid correlation-header response — PARTIAL:** invalid caller value is never propagated; a server correlation UUID is used for traceable rejection.
3. **Administration permission catalogue — BLOCKED:** permission syntax is frozen; exact endpoint-level `security.*` keys are not.
4. **Session idle timeout — BLOCKED:** no unapproved cross-module heartbeat/introspection mechanism will be introduced.
5. **Generic malformed-request normalization — BLOCKED:** do not invent a Security error merely to replace framework validation behavior.
6. **Authoritative OpenAPI availability — BLOCKED BY SOURCE:** approved `SECURITY_OPENAPI_v1.3.yaml` SHA-256 is `07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`, but the checksum-matching source is unavailable in the repository, wider Verigence GitHub search, File Library or recoverable context. Public lifecycle shapes must not be inferred.
7. **USER refresh location-context transition — RESOLVED:** `CLAR-004-001` permits moving the same ACTIVE session to another currently approved/assigned location only after complete policy re-evaluation; unapproved geo denies.
8. **Security-event taxonomy — OPEN:** `security.security_events.event_type` is free text in the approved schema. Do not invent event names solely because persistence permits them.
9. **Device BLOCKED vs REVOKED semantics — OPEN:** do not choose transition meaning or automatic session side-effects until approved source or explicit clarification defines them.

## Current execution direction

Continue Phase 4 only where lifecycle behavior is deterministic from approved artifacts/clarifications. Public lifecycle route wiring remains source-gated. The next internal decision point is the exact meaning and side-effects of device `BLOCKED` versus `REVOKED`.
