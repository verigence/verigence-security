# Verigence Security — Implementation Tasks

**Status:** SECURITY IMPLEMENTATION + DEV DEPLOYMENT COMPLETE  
**Created:** 2026-08-15  
**Updated:** 2026-08-16  
**Design:** `docs/SECURITY_CROSS_MODULE_AUTH_DESIGN_v1.0.md` / VSEC-SD-INT-001 v1.2

This file is the operational progress tracker for Security work introduced by approved authentication, authorization and cross-module integration decisions. It does not mark design-only work as implemented.

## Current position

**Tasks:** 4  
**COMPLETE:** 4  
**IN PROGRESS:** 0  
**BLOCKED:** 0  
**NOT STARTED:** 0

Security's approved authentication/OAuth implementation is complete and deployed in DEV. Railway project `verigence-security` (`a6808842-2e90-44f8-9172-63a905b24b5c`), service `verigence-security` (`cfc90262-4b33-419d-a874-4592de9e8db1`) deployed source commit `7f206e508a5d16c8ec4a77d3ead519042bfc7b68` as Railway deployment `c56c9777-6e9d-43a0-8c64-c22da73e6dd8`. GitHub Actions CI run `31935073699` passed for that exact commit. DEV deployment/verification run `31935073694` completed successfully.

The DEV verification applied the Security auth schema, configured Clerk as the upstream OAuth provider behind Security, provisioned and retained the dummy PC user `verigence.security.devtest@example.com` in Tenant `dev-auth-test`, verified live JWKS, confirmed unauthenticated `/oauth/token` reaches the OAuth handler and returns `invalid_client` rather than 404, issued and JWKS-validated a real Security USER token, issued and validated a Tenant-scoped SERVICE token, issued and validated a narrowed delegated USER token with `act.sub`, and verified that an unauthenticated authorization request routes through Security `/auth/login` to Clerk.

The retained DEV test user's Verigence user id is `dev-user-9351aaba-bf1c-4f43-902e-0c6f33d54aef`; its Clerk subject is `user_3HzNLQyYdmmY3SdqeTwXpae49W7`. The user is intentionally **not deleted** yet. Its generated password and OAuth client secrets remain managed runtime secrets and are not recorded here.

**Consumer binding note:** Security itself is live and verified with a controlled registered DEV OAuth client. The actual Audit Core Railway service still needs its own confidential client credential registered/synchronized with Security before a real Audit Core -> Security token request can be claimed as verified. That consumer binding belongs to the cross-module integration follow-up and does not reopen the completed Security server implementation/deployment tasks.

| ID | Task | Status | Deliverable | Acceptance | Dependency / note |
|---|---|---|---|---|---|
| SEC-INT-001 | Implement platform permissions, service integration and delegated OAuth token exchange | COMPLETE | Security capability for (a) Security user JWTs carrying the Tenant's effective cross-module platform `permissions[]`, (b) Tenant-scoped short-lived `SERVICE` tokens for approved module-owned/admin/background execution and (c) OAuth delegated token exchange/on-behalf-of tokens narrowed to user + integration + requested downstream authority | `src/verigence_security/settings.py`, `tokens.py` and `app.py`; `tests/test_oauth.py`; original implementation CI `31884091488`; current full regression CI `31935073699` passed. Live DEV run `31935073694` additionally issued and JWKS-validated SERVICE and delegated tokens. | Downstream token semantics remain VSEC-SD-INT-001 v1.2. |
| SEC-RBAC-001 | Implement default PC/TL/PM/CRM templates and Tenant-customizable role management | COMPLETE | Security-owned approved default cross-module role catalogue; persistent platform/Tenant role templates; Tenant onboarding seed; Super Admin/Tenant Admin management authorization; effective token resolution from Tenant role configuration | `config/default_role_templates.json`, `src/verigence_security/role_templates.py`, `database/0001_role_templates.sql`, `tests/test_role_templates.py`; original CI `31884922331`; current regression CI `31935073699` passed. Live dummy PC token contained the expected Audit Core + DI capture/upload permissions and did not contain `di.verification.write`. | Design: `docs/SECURITY_DEFAULT_ROLE_TEMPLATES_v1.0.md`. |
| SEC-AUTH-001 | Implement Security-owned interactive authentication, session and OAuth authorization-code flow | COMPLETE | Security-owned `/auth/login`, `/auth/callback`, `/auth/logout`, `/session`, `/oauth/authorize`, and `authorization_code` handling at `/oauth/token`; Clerk/upstream IdP remains behind Security; modules are registered OAuth clients; Security persists/resolves Verigence user/Tenant membership and issues the authoritative USER token | `src/verigence_security/auth.py`, `auth_store.py`, `upstream.py`, `app.py`, `settings.py`, `database/0002_auth.sql`, `tests/test_auth.py`, `tests/test_oauth.py`; original implementation CI `31933873217` passed 22 tests including PostgreSQL persistence; current exact-deploy CI `31935073699` passed. | Authorization codes are short-lived/single-use/client+redirect-bound; session/code secrets are stored hashed; public clients require PKCE; user/Tenant/roles cannot be self-asserted. |
| SEC-DEPLOY-001 | Deploy and verify Security OAuth/authentication service in Railway DEV | COMPLETE | Railway DEV runs the verified Security build containing the approved auth/OAuth endpoints and RBAC/token implementation; Neon contains the auth/session/membership schema; retained DEV user exists for controlled verification | Exact deployed commit `7f206e508a5d16c8ec4a77d3ead519042bfc7b68`; CI `31935073699` PASS; DEV verification run `31935073694` PASS; Railway deployment `c56c9777-6e9d-43a0-8c64-c22da73e6dd8`; schema applied; Clerk OAuth application configured; retained PC test user provisioned; live USER/SERVICE/delegated token issuance and JWKS validation PASS; login redirect to Clerk PASS; `/oauth/token` route no longer 404. | Security-side blocker is resolved. Actual Audit Core confidential-client binding remains a separate consumer-integration step before Audit Core `XMOD-SEC-01` is closed end-to-end. |

## Completion rule

A task becomes COMPLETE only after implementation and the stated positive/negative tests pass. Creating a task/design, committing defaults or observing a route locally does not complete the implementation. Deployment tasks additionally require evidence from the exact deployed commit and live DEV endpoint.
