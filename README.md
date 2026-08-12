# Verigence Security Service

Reviewed implementation baseline for **Verigence Security Design v1.3**.

> **Branch intent:** this baseline is suitable for `dev` review and continued implementation. It is **not production-complete**. See `docs/IMPLEMENTATION_STATUS.md` and `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md` before treating any endpoint as complete.

## Phase-1 infrastructure

- Railway — Security API runtime
- Clerk — USER authentication provider in UAT/Production
- Neon PostgreSQL — Security authorization and policy data

## Implementation stack

- Python 3.12+
- FastAPI
- SQLAlchemy 2 + psycopg 3
- Verigence-owned asymmetric Access JWT + JWKS

Python/FastAPI/SQLAlchemy and the initial RSA/RS256 JWT implementation are engineering choices for this repository; the approved Security domain contracts remain provider/framework neutral where designed.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
cp .env.example .env
uvicorn verigence_security.main:app --reload
```

The DEV mock-auth endpoint is registered only when `DEV_MOCK_AUTH_ENABLED=true` and its required DEV-only signing settings are explicitly configured.

## Database

The exact approved Security v1.3 PostgreSQL baseline is copied unchanged to:

`migrations/0001_security_baseline_v1.3.sql`

Use the Neon **direct** connection string for migration execution and the **pooled** connection string for runtime API traffic.

## Design review basis

Before this commit, the implementation was reviewed against the approved Security v1.3 OpenAPI and supporting design artifacts. The approved OpenAPI itself is not duplicated in this implementation commit; its reviewed SHA-256 is recorded in `docs/APPROVED_SOURCE_REFERENCE.md` so an altered/generated specification is not accidentally presented as the source of truth.

## Verification

```bash
pytest
ruff check src tests
mypy src
```

The pre-commit design review completed in the isolated build environment with:

- 30 pytest tests passing;
- Python compile/AST checks passing;
- exact match of the committed v1.3 SQL, decision-register, correlation-standard and operational-lifecycle sources;
- approved OpenAPI reviewed by SHA-256 and contract comparison;
- exact 42/42 v1.3 error-code/status match;
- static secret, legacy-permission and caller-authority scans passing.

`ruff`, `mypy`, package build and live Neon/Clerk integration remain CI/pre-merge gates because those tools/services were unavailable in the isolated review runtime.

## Critical safety behavior

- UAT/Production cannot start with DEV mock authentication enabled.
- UAT/Production cannot start with the mock network-risk adapter.
- Caller-supplied actor type, roles and permissions are never trusted.
- USER identity resolution validates the registered Security Principal type/status.
- MAC address is not the canonical device identifier.
- USER access requires an ACTIVE registered device, assigned geo location and valid time window.
- Explicit geo spoof/mock indication (`SUSPECTED`) denies USER access.
- Canonical permissions use dot notation such as `di.document.upload`; legacy colon permissions are not emitted in tokens.
- `X-Correlation-ID` is returned on normal responses, Security errors and unexpected HTTP 500 responses.
- `/health/ready` fails closed when database connectivity or Security signing keys are unavailable.

## Known incomplete v1.3 areas

The repository does **not** yet claim completion of persistent idempotency, device-enrollment administration, USER refresh/revoke, SYSTEM/SERVICE_INTEGRATION machine-token flows, activation readiness, retention purge, Tenant offboarding, full administration APIs, denied-event persistence, overlapping JWKS key rotation, production network-risk integration, live Clerk/Neon integration tests, cross-module session-idle-timeout enforcement semantics, or generic malformed-request 400/Problem normalization where v1.3 has no frozen validation error code.

See `docs/IMPLEMENTATION_STATUS.md` for the exact milestone boundary.
