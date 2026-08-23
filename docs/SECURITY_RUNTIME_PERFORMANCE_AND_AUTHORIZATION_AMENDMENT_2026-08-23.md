# Security Runtime Performance and Authorization Amendment

Date: 2026-08-23
Status: Approved implementation amendment for UC01 / UC02 runtime paths

## Objective

Keep the Web UI responsive without weakening the trust boundary. The browser continues to send the Security-issued human bearer token on protected requests, but repeated network work that is not required to establish trust must be removed from hot read paths.

## Decisions

### 1. Human token reuse and local validation

- The same human bearer token issued at login is reused by Web for subsequent protected requests until normal token expiry/refresh rules apply.
- Backend services validate the token on every protected request.
- Signature, issuer, audience, expiry and actor type validation remain mandatory.
- JWT verification must be local after the signing key has been obtained. A backend must not fetch JWKS on every API request.
- JWKS/public signing keys and the validator lifecycle are backend concerns. They are never trusted from browser cache or browser storage.

### 2. ServiceIntegration token reuse

- Backend-to-Security ServiceIntegration tokens are cached only in backend process memory.
- A valid cached token is reused instead of requesting a new machine token for every authorization call.
- Cache lifetime must never exceed the token lifetime; refresh occurs before expiry.
- This cache does not cache an authorization decision. Security may still be consulted when a live permission decision is required.

### 3. Read-only reference and master data

- Reading reference/master data must not require SuperAdmin merely because the data appears on an administration screen.
- Approved read-only reference/master endpoints require a valid authenticated human token only, unless a specific data domain has a separately documented stronger read restriction.
- Administrative mutations remain protected by their existing administrative authorization. Examples include Project creation/activation, role changes, master import confirmation, publish/retire and other state-changing operations.
- UC02 does not introduce a generic master-data result cache.
- Master result caching is deferred to UC03 and will be limited to master data proven to be repeatedly consumed by journey execution.

### 4. Lazy loading remains the Web pattern

- Web continues to load small resources independently when they are needed.
- Performance work must make each small API path cheap; it must not replace lazy loading with a large bootstrap payload.

### 5. Database connection handling

Database resilience is configured centrally in each backend connection pool, not implemented separately inside each API handler.

For PostgreSQL-backed services the standard is:

- one shared/reused SQLAlchemy Engine/pool per process/configured URL;
- `pool_pre_ping=True` so a dead pooled connection is rejected before reuse;
- a bounded pool checkout timeout;
- a bounded database connect timeout;
- a bounded PostgreSQL statement timeout.

There is no generic transaction replay or automatic write retry in this amendment. A database restart that terminates an already-running statement may still fail that request; the application must return a controlled error rather than blindly replaying a mutation.

### 6. UC01 pending-approval landing path

- Pending approvals remain lazy-loaded.
- The server-side pending status filter and result limit must be honored so the landing path does not retrieve the full USER directory when only pending registrations are requested.
- Security-issued human token verification in the Security service uses the configured local public key and must not introduce a JWKS network dependency.

## Scope boundaries

This amendment intentionally does not:

- cache browser authorization state;
- cache every Project Master in UC02;
- remove authentication from reference/master reads;
- weaken authorization for state-changing administration;
- combine unrelated Web calls into a single large response;
- introduce a general retry/orchestration framework.

## Implementation mapping

- Audit Core: reuse JWT validator/JWKS client, reuse ServiceIntegration token/client, remove live SuperAdmin attestation from the explicitly approved read-only reference/master paths, and harden the shared PostgreSQL pool.
- DI: keep local JWT/JWKS verification and remove live SuperAdmin attestation only from approved read-only Project Master catalogue/template/version reads. Project Master mutations remain SuperAdmin-protected.
- Security: retain local human-token verification and server-side filtering/pagination for UC01 USER-directory reads; existing database pool pre-ping remains the baseline.
