# Verigence Security Implementation Status — v0.1 Reviewed Baseline

This implementation is grounded in **Security Design Source v1.3**. It does not supersede the design.

A detailed code-to-design review is in `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`.

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
- **Real PostgreSQL repository validation — DONE:** 4/4 Neon integration tests pass, including actual `SELECT ... FOR UPDATE` serialization and representative CHECK/FK enforcement.
- **Phase 3 Railway DEV deployment — DONE:** the exact immutable GHCR image is deployed to the Railway DEV service instance using the environment-specific image source.
- **Railway runtime configuration — DONE for DEV:** Neon runtime DB connection, Security signing material, DEV mock identity configuration, DEV mock network-risk mode and trusted ingress-header setting are configured without committing secret values.
- **Deployed HTTPS smoke tests — DONE:** `/health/ready`, `/health/live` and `X-Correlation-ID` propagation pass against the public Railway DEV endpoint.
- **Deployed DEV USER E2E — DONE:** DEV mock identity → Railway Security API → Neon Tenant/device/location/schedule/RBAC evaluation → Security access-session/JWT issuance passes, with temporary fixture cleanup verified.

Evidence is recorded in `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`, `docs/PHASE_2_NEON_INTEGRATION.md` and `docs/PHASE_3_RAILWAY_DEV_VALIDATION.md`.

## Not yet implemented

The following v1.3 contracts remain for subsequent milestones and are intentionally not guessed or partially represented as complete:

- persistent idempotency storage/replay across stateless replicas;
- device enrollment/approval/block/revoke APIs;
- USER session refresh/revoke endpoints;
- active-device-limit enforcement under concurrency;
- complete denial-event persistence for device/session lifecycle flows;
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

## Design-to-implementation clarifications that remain open

1. **Idempotency persistence:** SEC-030 requires same-key replay across stateless replicas, but Security schema v1.3 has no idempotency-record table. The endpoint requires the header but v0.1 does not claim cross-replica replay semantics. A persistent idempotency store/table requires an approved design addition before this contract is complete.
2. **Invalid correlation-header response:** v1.3 says invalid caller correlation IDs are rejected and every response carries a correlation ID. v0.1 generates a new server-side UUID solely for the rejection response; the invalid caller value is never normalized or propagated. This should be made explicit in the next design baseline.
3. **Administration permission catalogue:** v1.3 freezes permission syntax but not the exact `security.*` permission required by every administration endpoint. v0.1 does not invent those keys.
4. **Session idle-timeout semantics:** v1.3 makes `session_idle_timeout_minutes` mandatory configuration, but DI/WPM validate short-lived Security JWTs locally and Security therefore does not observe ordinary downstream request activity. v0.1 does not invent a cross-module heartbeat/introspection mechanism. The exact definition of “activity” and how idle timeout is enforced across modules must be frozen before this policy can be claimed complete.
5. **Generic request-validation error contract:** v1.3 OpenAPI documents HTTP 400 `Problem` for bad requests, while the normative 42-code catalogue contains no generic malformed-request code. FastAPI/Pydantic therefore still emits framework HTTP 422 responses for malformed UUID/body/header validation (for example a missing `Idempotency-Key`). v0.1 does not invent a new client error code. This API-error normalization must be baselined before the runtime contract can be called fully OpenAPI-conformant.

## Verification at review and deployed DEV gates

- v0.1 review `pytest`: 30 passed.
- Python compile/AST checks: PASS.
- v1.3 OpenAPI/schema/decision/correlation/lifecycle copies: byte-identical to the approved solution artifacts.
- v1.3 error catalogue: 42/42 exact code and HTTP-status match.
- Static design gates: 24/24 PASS (including secret, legacy-permission, runtime OpenAPI and request-authority checks).
- GitHub CI: Ruff, strict Mypy, Pytest, package build and dependency consistency PASS on promoted phases.
- Neon DEV schema validation: PASS.
- Real Neon repository integration tests: 4/4 PASS.
- Railway DEV runtime deployment: PASS.
- Railway `/health/ready`: PASS (`databaseReady=true`, `signingKeyReady=true`).
- Railway `/health/live`: PASS.
- Deployed `X-Correlation-ID` propagation: PASS.
- Deployed DEV USER access-session E2E against Neon: PASS.
