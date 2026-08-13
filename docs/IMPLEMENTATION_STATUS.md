# Verigence Security Implementation Status — v0.1 Reviewed Baseline + Promoted Increments

This implementation is grounded in **Security Design Source v1.3**. It does not supersede the design.

A detailed code-to-design review of the initial baseline is in `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`. Later promoted increments and their validation evidence are tracked in `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`.

## Implemented and reviewed in v0.1

- FastAPI service foundation for Railway.
- Environment safety rules: DEV mock auth/network adapters cannot be enabled in UAT/Production.
- DEV mock signing secret and mock-token TTL must be explicit when mock auth is enabled.
- Exact `X-Correlation-ID` middleware for normal responses, Security errors and unexpected HTTP 500 responses.
- Clerk networkless JWT verification adapter using configured Clerk public key.
- DEV mock identity token issuer/verifier; no roles/permissions/Tenant membership can be injected.
- Security Principal USER actor-type/status check during identity mapping.
- Security RSA Access JWT issue/verify and single-key JWKS generation.
- Canonical permission validator (`di.document.upload` style) enforced before token issuance.
- Geo freshness/accuracy/integrity/radius logic with no hidden implementation-only clock-skew threshold.
- Time-window evaluator, including overnight windows.
- Provider-neutral network-risk adapter with deterministic DEV mock.
- Network-risk provider invocation kept outside the DB/device-lock transaction.
- Neon/PostgreSQL SQLAlchemy runtime Engine/session-factory reuse.
- Repository queries for USER identity, Tenant membership, device lock, assigned locations, schedules, overrides, effective RBAC and access-session persistence.
- USER `POST /security/v1/access-sessions` core path with required `Idempotency-Key`, transaction/device lock, policy evaluation, same-location active-session reuse, context conflict handling, evidence and JWT issuance.
- Reused-session token expiry remains capped by the original configured session maximum.
- Token-signing failure rolls back uncommitted session/evidence writes.
- DEV `POST /security/v1/dev/mock-auth/token` bootstrap implementation.
- `GET /.well-known/jwks.json`.
- `/health/live` and fail-closed `/health/ready` for database/signing-key readiness.
- Exact v1.3 database baseline included as initial migration source.
- Normative v1.3 error catalogue aligned exactly (42 codes/statuses).
- Unit/API tests for correlation, unexpected 500 traceability, geo/spoof stance, schedule windows, canonical permissions, environment safety, access-service transaction ordering/session conflict/session-max behavior and JWT key/claim behavior.

## Post-review validated milestones

The following milestones were completed after the v0.1 review baseline without changing the approved Security v1.3 normative artifacts:

- **Phase 1 CI quality gate — DONE:** design/static integrity, compile, Ruff, strict Mypy, Pytest, package build and dependency consistency are enforced through GitHub Actions.
- **Phase 2 Neon DEV integration — DONE:** the approved v1.3 `security` schema is deployed in Neon DEV and validated as 27 tables, 7 explicit indexes, 56 foreign keys and 57 CHECK constraints.
- **Real PostgreSQL repository validation — DONE:** repository reads, row locking and representative CHECK/FK enforcement pass on Neon.
- **Phase 3 Railway DEV deployment — DONE:** the exact immutable GHCR image is deployed to the Railway DEV service instance using the environment-specific image source.
- **Railway runtime configuration — DONE for DEV:** Neon runtime DB connection, Security signing material, DEV mock identity configuration, DEV mock network-risk mode and trusted ingress-header setting are configured without committing secret values.
- **Deployed HTTPS smoke tests — DONE:** `/health/ready`, `/health/live` and `X-Correlation-ID` propagation pass against the public Railway DEV endpoint.
- **Deployed DEV USER E2E — DONE:** DEV mock identity → Railway Security API → Neon Tenant/device/location/schedule/RBAC evaluation → Security access-session/JWT issuance passes, with temporary fixture cleanup verified.
- **Phase 4 Increment 1 — DONE:** PENDING device/enrollment persistence, approval persistence transition, device-limit serialization primitives, scoped USER session revoke persistence primitive and one-ACTIVE-session PostgreSQL invariant are validated on Neon and promoted through PR #19.
- **Phase 4 Increment 2 — DONE:** configured `max_active_devices_per_user` is enforced under concurrent approval attempts; real Neon validation proves exactly one of two simultaneous approvals succeeds when the Tenant limit is one. Promoted through PR #20.
- **Phase 4 Increment 3 — DONE:** missing USER refresh geo raises normative `GEO_REQUIRED`; scoped USER session revoke is transactional and does not attempt pre-`exp` invalidation of an already-issued JWT. Real Neon run `31672322586` passed 8/8 Phase 4 integration tests; PR #22, post-merge Security CI and Railway smoke checks are green.

Evidence is recorded in `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`, `docs/PHASE_2_NEON_INTEGRATION.md`, `docs/PHASE_3_RAILWAY_DEV_VALIDATION.md` and `docs/PHASE_4_DEVICE_SESSION_LIFECYCLE.md`.

## Not yet implemented / not yet complete

The following v1.3 contracts remain for subsequent milestones and are intentionally not guessed or partially represented as complete:

- persistent idempotency storage/replay across stateless replicas;
- public device enrollment/approval/block/revoke route contracts and wiring;
- complete USER session refresh policy re-evaluation, expiry/evidence/token issuance and public route;
- exact approved refresh behavior when fresh valid geo resolves to a different assigned location than the ACTIVE session context;
- USER session revoke public route wiring;
- complete denial-event persistence for device/session lifecycle flows;
- deployed Phase 4 lifecycle E2E through the public routes;
- machine-principal credentials and machine access-token endpoint;
- SYSTEM/SERVICE_INTEGRATION administrator endpoints;
- Tenant activation-readiness endpoint and activation application service;
- retention-policy maintenance purge implementation;
- Tenant offboarding application service/endpoints;
- full Security administration APIs for users/memberships/roles/locations/schedules/policies;
- complete denied authentication/authorization/security-event persistence;
- endpoint-level administration permission catalogue where exact permission keys must be frozen;
- overlapping JWKS old/new key rotation and verifier-cache transition support;
- production network-risk provider adapter (provider not selected in v1.3 design);
- Clerk invitation/onboarding API calls and live Clerk integration test.

These are implementation milestones, not removed scope.

## Design/source clarifications that remain open

1. **Idempotency persistence:** SEC-030 requires same-key replay across stateless replicas, but Security schema v1.3 has no idempotency-record table. The endpoint requires the header but the implementation does not claim cross-replica replay semantics. A persistent idempotency store/table requires an approved design addition before this contract is complete.
2. **Invalid correlation-header response:** v1.3 says invalid caller correlation IDs are rejected and every response carries a correlation ID. The implementation generates a new server-side UUID solely for the rejection response; the invalid caller value is never normalized or propagated.
3. **Administration permission catalogue:** v1.3 freezes permission syntax but not the exact `security.*` permission required by every administration endpoint. Do not invent those keys.
4. **Session idle-timeout semantics:** v1.3 makes `session_idle_timeout_minutes` mandatory configuration, but DI/WPM locally validate Security JWTs and Security therefore does not observe ordinary downstream request activity. Do not invent a cross-module heartbeat/introspection mechanism.
5. **Generic request-validation error contract:** v1.3 OpenAPI documents HTTP 400 `Problem` for bad requests, while the normative 42-code catalogue contains no generic malformed-request code. Do not invent a new client error code.
6. **Authoritative OpenAPI source availability:** `SECURITY_OPENAPI_v1.3.yaml` is referenced by approved SHA-256 `07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37`, but the checksum-matching artifact is not available in the repository, wider Verigence GitHub code search, File Library or recoverable context. Public lifecycle request/response/security shapes must not be inferred.
7. **USER refresh location-context transition:** committed v1.3 sources require fresh geo for USER refresh, but do not deterministically state what to do when valid fresh geo resolves to a different assigned location than the ACTIVE session. Do not choose reuse, conflict, revoke/recreate or context switch by implementation convenience.

## Verification at review and deployed DEV gates

- v0.1 review `pytest`: 30 passed.
- Python compile/AST checks: PASS.
- v1.3 approved-artifact integrity/static gates: PASS.
- v1.3 error catalogue: 42/42 exact code and HTTP-status match.
- GitHub CI: Ruff, strict Mypy, Pytest, package build and dependency consistency PASS on promoted phases.
- Neon DEV schema validation: PASS.
- Real Neon repository/lifecycle integration tests: PASS; Phase 4 latest run `31672322586` = 8/8 PASS.
- Railway DEV runtime deployment: PASS.
- Railway `/health/ready`: PASS (`databaseReady=true`, `signingKeyReady=true`).
- Railway `/health/live`: PASS.
- Deployed `X-Correlation-ID` propagation: PASS.
- Deployed DEV USER access-session E2E against Neon: PASS.
- Phase 4 Increment 3 post-merge Security CI `31672476255`: PASS.
- Phase 4 Increment 3 post-merge Railway deployment/smoke `31672476267`: PASS.
