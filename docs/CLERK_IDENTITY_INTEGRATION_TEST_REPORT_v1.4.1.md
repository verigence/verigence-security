# Verigence Security — Clerk Identity Integration Test Report v1.4.1

**Date:** 2026-08-13  
**Repository:** `verigence/verigence-security`  
**Feature branch:** `feature/clerk-live-integration-v1.4.1`  
**Validated implementation head:** `fefe1088b3ab3e51714434e03458c7aec6007268`  
**Result:** IMPLEMENTATION VALIDATED — LIVE CLERK E2E PENDING REAL SUPER ADMIN USER ID

## Scope validated

The backend-only Clerk cutover was validated against the approved v1.4.1 boundary. UI work is excluded and remains a separate module.

Validated behavior includes:

- Clerk session JWT verification for human identity;
- one-time first Platform Super Admin claim;
- configured Clerk subject matching for bootstrap;
- Security USER plus CLERK external-identity creation/resolution;
- Security-owned Platform role and permission evaluation;
- subsequent bootstrap denial after an ACTIVE Platform Super Admin exists;
- Clerk-backed Platform Admin session exchange into the existing Security Platform JWT;
- legacy local Platform password flow removed from the normal runtime path;
- no local credential row created for the Clerk-backed Super Admin;
- invitation acceptance and self-onboarding remain provider-neutral and compatible with Clerk identity;
- Railway deployment workflow uses separate workspace/API and project-token responsibilities.

## Security CI evidence

**Run:** `31727506715`  
**Head:** `fefe1088b3ab3e51714434e03458c7aec6007268`  
**Result:** PASS

Passed gates:

- approved design/static safety checks;
- compile;
- Ruff;
- Mypy;
- tests;
- package build;
- dependency consistency.

## Real Neon/PostgreSQL evidence

**Run:** `31727503789`  
**Head:** `fefe1088b3ab3e51714434e03458c7aec6007268`  
**Result:** PASS

The workflow successfully verified the immutable v1.3 migration digest, applied the idempotent v1.4 Admin migration, and ran the full Phase 5 PostgreSQL administration integration suite.

The immediately preceding Clerk implementation run `31727048102` executed 19 Phase 5 PostgreSQL integration tests and passed 19/19. The exact-head run repeated the same Phase 5 suite after the Railway deployment-workflow correction and also passed.

## Clerk Platform scenarios validated

The real PostgreSQL integration coverage proves:

1. the former local-password request shape cannot authenticate without Clerk identity;
2. a Clerk token with the wrong bootstrap subject is denied;
3. the first correctly matched Clerk subject can claim Platform Super Admin;
4. a second claim is denied once an ACTIVE Platform Super Admin exists;
5. the Clerk-backed administrator can obtain a Security Platform Admin JWT;
6. the Security Platform JWT works for `/platform/me` and direct Tenant administration;
7. the persisted external identity is `CLERK` and maps to the authenticated Clerk subject;
8. the Clerk-backed Super Admin has no local credential row;
9. Tenant role seeding, self-onboarding configuration, and Admin audit remain functional.

The first-claim invariant is serialized at the PostgreSQL transaction boundary so concurrent application instances cannot both complete the initial claim.

## Railway deployment workflow validation

The repository workflow now follows this responsibility split:

```text
Security CI on exact dev SHA
        ↓
Docker build in GitHub Actions
        ↓
GHCR immutable sha256 digest
        ↓
RAILWAY_API_TOKEN
source-image mutation
        ↓
RAILWAY_TOKEN
DEV deployment/status monitoring
        ↓
Railway SUCCESS
        ↓
readiness / liveness / correlation checks
```

Both credentials are required by the workflow, and the project token is validated against the expected DEV project and environment before deployment.

## Non-blocking warnings

The Neon suite reported two existing warnings that did not fail validation:

- a TestClient/httpx deprecation warning from the dependency stack;
- an SQLAlchemy transaction-cleanup warning in the existing module-catalog test.

These are maintenance items, not Clerk-cutover blockers.

## Live E2E still required

The real deployed bootstrap cannot be completed until the intended first Platform Super Admin Clerk `user_...` identifier is supplied.

After that identifier is available, the remaining operational proof is:

1. configure the real Clerk DEV verification values and bootstrap user ID in Railway;
2. temporarily enable bootstrap;
3. authenticate the intended user through Clerk and call the deployed bootstrap claim;
4. verify the Security USER, CLERK identity, Platform role, and audit in Neon DEV;
5. prove a second claim is denied;
6. disable bootstrap;
7. verify deployed Clerk-backed Platform login and `/platform/me`;
8. record the deployment and E2E evidence in the canonical tracker.

No placeholder user ID will be used for a live bootstrap.

## Conclusion

The v1.4.1 Clerk backend implementation is code-complete and has passed both Security CI and real Neon/PostgreSQL validation. The only remaining Clerk cutover gate is the live deployed proof using the real immutable Clerk user ID for the intended first Platform Super Admin.
