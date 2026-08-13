# Verigence Security — Clerk Backend Authentication Facade Design v1.4.2

**Status:** APPROVED IMPLEMENTATION AMENDMENT  
**Date:** 2026-08-13  
**Repository:** `verigence/verigence-security`  
**Applies to:** human authentication, Clerk integration, onboarding and Platform Super Admin bootstrap  
**Supersedes only:** the client-to-Clerk / Clerk-session-JWT assumptions in `SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` where they conflict with this amendment.  
**Does not supersede:** Security-owned Tenant/RBAC/Group/device/geo/schedule/access-policy decisions or module authorization rules.

---

## 1. Governing decision

Mobile and Web clients MUST communicate only with Verigence Platform/Security APIs.

They MUST NOT communicate directly with Clerk and MUST NOT contain Clerk SDK configuration, Clerk publishable keys,
Clerk secret keys, Clerk session tokens, or Clerk Organization/RBAC state.

The governing split is now:

> **Clerk owns human credential storage and credential verification. Verigence Security owns the public authentication facade, Verigence sessions/tokens, authorization, Tenant governance and access policy.**

---

## 2. Verified Clerk Backend API capabilities used

Implementation is limited to Clerk capabilities verified from official Clerk documentation:

- create users through Clerk Backend API `POST /users` / `createUser()`;
- lookup users through the Backend Users API;
- verify a user's password through `POST /users/{user_id}/verify_password` / `verifyPassword()`;
- verify TOTP/backup code through `POST /users/{user_id}/verify_totp` / `verifyTOTP()` when MFA is enabled later;
- backend user/session management operations supported by Clerk Backend API.

Important verified behavior: Clerk Backend `createUser()` automatically marks email/phone values supplied during
creation as verified. Therefore v1.4.2 MUST NOT claim that backend-created users completed Clerk email/phone
ownership verification.

If future policy requires Clerk-managed email/SMS ownership verification, a separate approved design must use an
appropriate Clerk Frontend API custom flow or Frontend API proxy through the Verigence domain. That is not part of
this increment.

---

## 3. Network boundary

```text
Mobile / Web
     |
     | HTTPS — Verigence API only
     v
Verigence Security
     |
     | server-to-server HTTPS
     | Clerk Secret Key held only in backend environment
     v
Clerk Backend API
```

### RULE-CLERK-BE-001

No Mobile/Web request is sent directly to Clerk.

### RULE-CLERK-BE-002

`CLERK_SECRET_KEY` is a backend deployment secret and MUST never be returned to clients, stored in database rows,
logged, committed to Git, or included in a container image.

### RULE-CLERK-BE-003

Passwords/TOTP values received by Security are transient request secrets. Security may pass them to Clerk over TLS
for verification but MUST NOT persist, hash, audit, trace, or log them.

---

## 4. Runtime authentication model

### 4.1 Normal USER login

```text
1. Mobile/Web -> POST Verigence login API
      identifier + password
      + Tenant/device/geo context required by Security access flow
2. Security resolves the Clerk user through Clerk Backend API.
3. Security calls Clerk verifyPassword(user_id, password).
4. If later enabled and required, Security calls Clerk verifyTOTP(user_id, code).
5. Clerk confirms credential validity only.
6. Security resolves Clerk user ID -> Security USER through `external_identities`.
7. Security evaluates:
      principal/user state
      Tenant membership
      device state
      geo/location
      schedule
      network policy
      Security Control Registry
      effective roles/permissions
8. Security creates/reuses its Verigence access session.
9. Security issues the Verigence Security JWT.
10. Mobile/Web uses only the Verigence JWT thereafter.
```

A Clerk password verification success alone never grants Verigence access.

### 4.2 No Clerk client session dependency

The client does not receive a Clerk session JWT in this architecture.

Security's existing `access_sessions` and Security JWT lifecycle remain the Verigence application session/access
contract. Clerk remains the credential verifier and user credential store.

DI/WPM continue receiving only Verigence Security JWTs.

---

## 5. Self-onboarding

Self-onboarding is backend-only and remains approval-gated.

```text
1. Person submits to Verigence:
      Tenant code
      Tenant onboarding token
      display name
      email/approved identifier
      password
2. Security validates Tenant exists and self-onboarding is enabled.
3. Security validates Tenant onboarding token BEFORE Clerk user creation.
4. Security checks whether a Clerk user already exists for the identifier.
5. If none exists, Security creates the Clerk user through Backend API.
6. Security creates/resolves Security USER and CLERK external identity mapping.
7. Tenant membership remains PENDING.
8. Self-onboarding request remains PENDING_ADMIN_APPROVAL.
9. Password is discarded from process memory after the Clerk call and never persisted/logged.
10. Tenant Admin approves/rejects in Security.
11. Only approval can activate non-privileged Tenant access.
12. Privileged roles remain pending maker-checker.
```

The Tenant onboarding token is still an API submission gate, not an identity credential.

---

## 6. Invitation onboarding

Verigence invitation remains authoritative.

Two supported backend paths are allowed:

- existing Clerk user: Security verifies that user's Clerk password through Backend API before binding/acceptance;
- new Clerk user: after invitation-token validation, Security creates the Clerk user through Backend API, then binds
  the Clerk user ID to the invited Security USER.

The exact invitation API request will never expose Clerk-specific objects to the client.

---

## 7. Platform Super Admin bootstrap

The intended first Super Admin is still pre-provisioned in Clerk first, either from Clerk Dashboard or an
operator-controlled backend process.

Deployment stores Clerk's immutable user ID:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=<Clerk user ID>
```

First bootstrap flow becomes backend-only:

```text
1. Intended Super Admin enters identifier/password in Verigence UI.
2. UI -> Verigence bootstrap claim API only.
3. Security resolves Clerk user via Backend API.
4. Security verifies password through Clerk Backend API.
5. Security requires returned Clerk user ID == configured bootstrap Clerk user ID.
6. Security requires zero ACTIVE platform.super_admin assignments.
7. Security transactionally creates/resolves Security USER + CLERK mapping.
8. Security assigns platform.super_admin.
9. Security writes redacted Admin audit evidence.
10. Security issues a dedicated Verigence Platform Admin token.
11. Bootstrap permanently closes while an ACTIVE Super Admin exists.
```

No Security-managed bootstrap password exists in the target runtime.

---

## 8. Platform Admin login after bootstrap

```text
Mobile/Web
  -> POST /security/v1/platform/auth/session
     identifier + password
  -> Security resolves Clerk user
  -> Clerk Backend verifyPassword
  -> Security resolves ACTIVE Platform roles/permissions
  -> Security issues `aud=verigence-security-admin` token
```

Existing local-password `/platform/auth/login` and `/platform/auth/change-password` routes are transitional debt
and MUST be disabled from the deployed normal path after this increment.

---

## 9. Environment configuration

All environment-specific configuration lives in environment variables / Railway secrets.

Required backend configuration for this architecture:

```text
CLERK_SECRET_KEY
CLERK_BACKEND_API_URL=https://api.clerk.com/v1
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID
PLATFORM_BOOTSTRAP_ENABLED
```

Existing Security signing/database/network variables remain unchanged.

`CLERK_SECRET_KEY` and actual bootstrap Clerk user ID values MUST NOT appear in `.env.example`; only placeholders
or blank documented variables are permitted.

`CLERK_PUBLISHABLE_KEY` is not required by Mobile/Web because those clients do not use Clerk directly.

The former `PLATFORM_BOOTSTRAP_LOGIN` and `PLATFORM_BOOTSTRAP_PASSWORD` variables are deprecated and must not be
required after cutover.

---

## 10. Failure and cross-path rules

1. unknown Clerk identifier -> generic authentication failure; do not disclose account existence;
2. wrong password -> generic authentication failure;
3. Clerk unavailable/timeout -> authentication unavailable; do not fall back to local password auth;
4. Clerk authenticates but Security USER missing -> no Tenant access unless an approved onboarding/bootstrap flow
   creates/binds the Security USER;
5. Clerk authenticates but membership PENDING/SUSPENDED/ENDED -> Security denies Tenant access;
6. Clerk authenticates but device/geo/schedule/network fails -> Security denies access;
7. wrong bootstrap Clerk user -> bootstrap denied even with correct password;
8. second/concurrent bootstrap -> at most one first ACTIVE Super Admin assignment succeeds;
9. duplicate Clerk identifier result -> fail closed rather than guessing;
10. existing Clerk subject mapped to another Security USER -> fail closed;
11. Clerk Organizations/RBAC metadata has no authorization effect;
12. no Clerk credential material appears in Admin audit snapshots.

---

## 11. Revised Clerk integration definition of done

The Clerk backend-facade increment is DONE only when:

1. design v1.4.2 and tracker are merged;
2. backend Clerk client uses `CLERK_SECRET_KEY` only from environment;
3. Clerk user lookup/create/password verification are server-to-server;
4. Mobile/Web Clerk direct dependency is zero;
5. first Super Admin bootstrap claim verifies credentials via Clerk Backend API and matches immutable configured
   Clerk user ID;
6. subsequent Platform Admin login verifies via Clerk Backend API and returns Security Platform Admin JWT;
7. local Platform password login/change-password are disabled from normal deployed runtime;
8. normal USER credential authentication can drive existing Security access-session issuance without a client Clerk
   token;
9. self-onboarding can create/bind Clerk identity only after Tenant onboarding-token validation and remains PENDING;
10. invitation acceptance follows the same backend identity boundary;
11. password/TOTP values are never persisted/logged/audited;
12. Neon tests pass;
13. Security CI passes;
14. exact merge commit deploys to Railway DEV;
15. live Clerk Backend API E2E proves authentication -> Security authorization/token issuance;
16. tracker/status/recovery evidence is updated.

---

## 12. Explicitly deferred

This amendment does not implement or invent:

- email/SMS ownership verification for Backend-API-created Clerk users;
- Clerk Frontend API proxy/custom flows;
- exact MFA/TOTP enrollment UX or mandatory MFA threshold;
- Clerk webhook-to-Security lifecycle mutations;
- OAuth/social/enterprise SSO backend facade;
- machine identities;
- device BLOCKED/REVOKED semantics;
- complete Tenant activation prerequisites.

---

## 13. Final model

```text
                    MOBILE / WEB
                         |
                Verigence APIs only
                         |
                         v
               VERIGENCE SECURITY
               /                 \
      authentication facade      authorization/access policy
               |                 |
               v                 v
       CLERK BACKEND API      Security USER/Tenant/RBAC
   credential/user storage       device/geo/schedule
   password/TOTP verification    permissions/sessions
               |                 |
               +--------+--------+
                        v
                Verigence Security JWT
                        |
                  +-----+-----+
                  |           |
                 DI          WPM
```

> **The client talks only to Verigence. Clerk validates human credentials behind the Security boundary; Security
> decides and issues Verigence access.**
