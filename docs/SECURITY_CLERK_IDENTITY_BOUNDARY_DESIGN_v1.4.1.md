# Verigence Security — Clerk Identity Boundary and Bootstrap Design v1.4.1

**Status:** APPROVED IMPLEMENTATION AMENDMENT  
**Date:** 2026-08-13  
**Repository:** `verigence/verigence-security`  
**Applies to:** Admin Control Plane v1.4 and USER identity/authentication flows  
**Supersedes only:** the local-password Platform Super Admin authentication decisions in sections 13, 17.1, 18.4, 19.2, 23, 24 and 25 of `SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` where they conflict with this amendment.  
**Does not supersede:** Security v1.3 authorization/access-policy decisions, Tenant RBAC, Groups, onboarding approval, module permissions, DI/WPM token authorization or other v1.4 control-plane rules.

---

## 1. Purpose

This amendment freezes the boundary between Clerk and Verigence Security before further implementation.

The objective is to avoid two authentication systems and two authorization authorities.

The governing split is:

> **Clerk owns human identity authentication. Verigence Security owns authorization, Tenant governance and Verigence access policy.**

Security MUST NOT implement a second general-purpose human password/MFA/session-recovery system.

---

## 2. Verified Clerk capabilities used by this design

The following are current Clerk capabilities verified from Clerk's official documentation on 2026-08-13:

1. Clerk can create/manage users through the Clerk Dashboard or Backend API.
2. Clerk authenticates users and issues short-lived signed session JWTs.
3. Clerk session JWTs can be verified by backend services using Clerk public/JWKS material.
4. Clerk can require MFA for all users; incomplete required session tasks keep the session pending rather than fully signed in.
5. Clerk session JWTs include factor-verification age (`fva`) information that can be used when sensitive operations require recent factor verification.
6. Clerk also offers Organizations, roles and permissions, but Verigence does **not** use Clerk Organizations/RBAC as the authorization authority.

Official references reviewed:

- Clerk Docs — `createUser()` / Users Backend API
- Clerk Docs — Manual JWT verification
- Clerk Docs — Session tokens
- Clerk Docs — Sign-up and sign-in options / Require MFA
- Clerk Docs — Session tasks
- Clerk Docs — Organizations roles and permissions

Clerk product behavior outside these verified capabilities MUST NOT be assumed during implementation.

---

## 3. Non-negotiable ownership boundary

### RULE-ID-001 — Clerk owns human authentication

Clerk owns:

- sign-up/sign-in authentication;
- password storage and verification;
- password reset/recovery;
- email/phone verification as configured in Clerk;
- MFA/second-factor setup and verification;
- social login/SSO when later enabled;
- Clerk authentication sessions;
- Clerk session JWT issuance;
- credential compromise/lockout functionality provided by Clerk.

Security MUST NOT duplicate these capabilities for normal human accounts.

### RULE-ID-002 — Security owns Verigence authorization

Security owns:

- `security_principals` and Verigence USER identity;
- mapping from Clerk `user_id`/subject to Verigence USER;
- Platform administrator assignments;
- Tenants;
- Tenant memberships;
- Groups;
- Tenant roles;
- module permission catalogue and role templates;
- effective permissions;
- explicit locations/schedules;
- device state;
- geo/network/schedule/access-policy checks;
- Tenant onboarding tokens;
- invitation/self-onboarding workflow state;
- human Admin approval;
- privileged maker-checker;
- Verigence business/Admin access JWTs;
- Security audit evidence.

### RULE-ID-003 — Clerk Organizations/RBAC is not the Verigence authorization authority

Verigence MUST NOT maintain live Tenant membership/RBAC in both Clerk Organizations and Security.

Do not synchronize Clerk Organization roles into Security as an authoritative authorization source.

Verigence Tenant membership and authorization remain Security-owned.

### RULE-ID-004 — Modules authorize on Security permissions

DI, WPM and future modules continue authorizing from Security-issued `permissions[]` claims.

They do not authorize from Clerk roles or Clerk Organization membership.

---

## 4. Canonical identity relationship

```text
Clerk User
  clerk_user_id / JWT sub
          |
          | external identity mapping
          v
Security USER
  security.users.user_id
          |
          +-- Platform role assignments (optional)
          |
          +-- Tenant memberships
                 |
                 +-- Direct Tenant roles
                 +-- Group-inherited Tenant roles
                 +-- Explicit location/schedule assignments
                 +-- Device/access-policy state
```

The Clerk identifier is authentication identity. The Security USER ID is the Verigence domain/security principal.

One does not replace the other.

---

## 5. Normal USER authentication and access flow

### 5.1 Authentication sequence

```text
User
  |
  v
Clerk Sign-up / Sign-in
  |
  +-- password/passkey/SSO as configured
  +-- email/phone verification as configured
  +-- MFA/session task completion as configured
  |
  v
Clerk signed session JWT
  |
  v
Verigence Security verifies Clerk JWT
  |
  +-- signature / issuer / expiry
  +-- authorized party where configured
  +-- authenticated Clerk subject
  |
  v
Security resolves external identity
  Clerk subject -> Security USER
```

Authentication success alone does not grant Tenant access.

### 5.2 Authorization sequence

After Clerk identity is authenticated, Security evaluates its own state:

```text
Security USER
  -> Tenant membership
  -> role/group RBAC
  -> registered device
  -> fresh geo when required
  -> assigned approved location
  -> schedule
  -> network/VPN policy
  -> Security controls
  -> effective permissions
  -> Verigence Security JWT
```

DI/WPM then verify the Verigence Security JWT and enforce module permissions locally.

### RULE-ID-005

A valid Clerk JWT proves authenticated identity only. It does not by itself prove:

- Tenant membership;
- role;
- Group membership;
- permission;
- approved device;
- approved location;
- schedule access;
- DI/WPM business authorization.

---

## 6. Team self-onboarding with Clerk

Self-onboarding remains a Security workflow.

### 6.1 Flow

```text
1. Person completes Clerk sign-up/sign-in.
2. Clerk completes configured identity verification/MFA requirements.
3. Person submits:
      authenticated Clerk session JWT
      + Tenant code
      + Tenant self-onboarding token
4. Security verifies Clerk authentication.
5. Security verifies:
      Tenant exists
      admin.self_onboarding control is enabled
      Tenant onboarding setting is ACTIVE
      supplied Tenant onboarding token matches stored Argon2id hash
6. Security resolves or creates Security USER + external identity mapping.
7. Security creates/retains Tenant membership = PENDING.
8. Security creates self-onboarding request = PENDING_ADMIN_APPROVAL.
9. Tenant Admin reviews request.
10. Admin assigns approved roles/groups/locations/schedules.
11. Non-privileged approved onboarding may activate membership.
12. Privileged role requests remain pending for maker-checker.
```

### RULE-ID-006

The Tenant onboarding token is a shared Tenant-scoped submission gate, not an identity credential and not an authorization token.

### RULE-ID-007

Self-onboarding never allows the applicant to choose or activate their own role, Group, permission, location or administrator privilege.

---

## 7. Invitation onboarding with Clerk

Invitation-led onboarding remains optional but supported.

```text
Tenant/Platform Admin creates Verigence invitation
  -> proposed Security access is inert
  -> recipient authenticates with Clerk
  -> recipient presents one-time invitation acceptance value
  -> Security binds authenticated Clerk identity to invited Security USER
  -> non-privileged access can become effective after acceptance
  -> privileged access remains pending maker-checker
```

Security invitation state is authoritative for Tenant onboarding.

Clerk Organization invitations MUST NOT replace this workflow because Verigence invitation state includes Security-specific Tenant roles, Groups, locations, privileged approval and audit requirements.

---

## 8. Platform Super Admin bootstrap — final model

This section replaces the local-password bootstrap model from Admin Control Plane v1.4.

### RULE-BOOT-CLERK-001 — First Super Admin is created in Clerk first

Before first Verigence Security bootstrap, an operator creates the intended first Platform Super Admin as a normal human user in the configured Clerk instance.

This may be done using the Clerk Dashboard or an approved operator-controlled Clerk Backend API process.

Clerk owns that user's password/passkey/MFA/recovery credentials.

Security stores none of them.

### RULE-BOOT-CLERK-002 — Bootstrap identity uses immutable Clerk user ID

After the Clerk user exists, deployment configuration stores its immutable Clerk user identifier, for example:

```text
SECURITY_BOOTSTRAP_SUPER_ADMIN_CLERK_USER_ID=<Clerk user ID>
```

The actual variable name may be finalized during implementation, but the value MUST be Clerk's immutable user identifier, not display name or email.

The value is deployment configuration, not a password.

### RULE-BOOT-CLERK-003 — Bootstrap is an authenticated one-time claim

Initial Super Admin provisioning uses a one-time Security bootstrap claim endpoint, conceptually:

```text
POST /security/v1/platform/bootstrap/claim
Authorization: Bearer <Clerk session JWT>
```

No Security username/password is accepted.

The claim succeeds only when **all** conditions are true:

1. bootstrap mode is explicitly enabled for the environment;
2. Clerk JWT is valid using the configured Clerk verifier;
3. JWT `sub` equals configured bootstrap Clerk user ID;
4. no ACTIVE `platform.super_admin` assignment exists;
5. corresponding Security USER/external identity either does not exist or resolves consistently to the same Clerk subject;
6. the operation is executed transactionally;
7. an Admin audit record is written without credential material.

### RULE-BOOT-CLERK-004 — Bootstrap is permanently fail-closed after success

After the first ACTIVE `platform.super_admin` assignment is created:

- bootstrap claim MUST return denied/not-available regardless of configured bootstrap user ID;
- restart MUST NOT reopen bootstrap;
- changing deployment configuration MUST NOT replace the existing Super Admin automatically;
- no bootstrap path may delete or rotate Clerk credentials.

The operator should remove/disable bootstrap deployment configuration after successful initialization.

### RULE-BOOT-CLERK-005 — No shared bootstrap password

The previous temporary Security bootstrap password is retired as a target design.

`security.local_user_credentials` MUST NOT be used for normal Platform Super Admin authentication after Clerk integration.

Existing Increment-B local credential code/database rows are migration debt until the Clerk cutover increment explicitly disables/removes their runtime use.

Historical rows MUST NOT be deleted without a migration/retention decision.

### RULE-BOOT-CLERK-006 — Super Admin authentication thereafter is Clerk authentication

After bootstrap:

```text
Platform Super Admin
  -> signs in through Clerk
  -> presents Clerk session JWT to Security
  -> Security resolves Clerk subject -> Security USER
  -> Security resolves ACTIVE Platform roles/permissions
  -> Security authorizes Platform Admin API
```

Security may issue a dedicated control-plane JWT if required by the existing architecture, but that token is derived from an already-authenticated Clerk identity and MUST NOT require a separate Security password.

### RULE-BOOT-CLERK-007 — MFA

For Platform Super Admin and privileged Security administrators, Clerk MFA SHOULD be required in the Clerk instance configuration before production/UAT approval.

Where a sensitive operation requires recent factor verification, implementation may use Clerk's signed factor-verification age (`fva`) only after the exact freshness requirement is separately approved and documented. No arbitrary threshold is introduced by this amendment.

---

## 9. Super Admin first-start operating sequence

```text
PRE-DEPLOYMENT

1. Configure Clerk application.
2. Enable desired sign-in method(s).
3. Configure required email/phone verification as appropriate.
4. Enable required MFA for privileged human access before UAT/Production.
5. Create first intended Super Admin user in Clerk.
6. Record Clerk immutable user ID.
7. Configure Security/Railway with:
      Clerk issuer/JWT verification material
      authorized parties
      bootstrap-enabled flag
      bootstrap Clerk user ID
8. Deploy Security.

FIRST CLAIM

9. Intended Super Admin signs in through Clerk.
10. Clerk completes authentication/session tasks.
11. UI/client sends Clerk session JWT to Security bootstrap claim.
12. Security verifies Clerk JWT.
13. Security requires JWT subject == configured bootstrap Clerk user ID.
14. Security verifies zero ACTIVE Platform Super Admin assignments.
15. Security transactionally:
       creates/resolves Security USER
       creates/resolves CLERK external identity mapping
       creates ACTIVE platform.super_admin assignment
       writes Admin audit evidence
16. Claim succeeds.

POST-CLAIM

17. Security bootstrap endpoint becomes permanently unavailable while an ACTIVE Super Admin exists.
18. Operator disables/removes bootstrap deployment configuration.
19. Super Admin creates Tenants / additional Platform administrators using normal authorized Admin APIs.
20. Additional Platform Admins authenticate with Clerk and receive Security Platform-role assignments through controlled administration, never via bootstrap.
```

---

## 10. Platform Admin token boundary

If Verigence continues to issue a dedicated Platform Admin JWT:

```text
issuer   = verigence-security
audience = verigence-security-admin
```

its issuance MUST require a valid Clerk-authenticated Security USER with effective ACTIVE Platform role/permission.

It MUST NOT be accepted by DI/WPM business APIs.

No Platform token endpoint may accept a Security-managed password after Clerk cutover.

---

## 11. What remains Security-owned after Clerk integration

Clerk integration does **not** remove or move these Security capabilities:

- Platform roles;
- Tenant roles;
- Groups;
- module permissions/templates;
- Tenant membership;
- Tenant self-onboarding token;
- Tenant invitation state;
- self-onboarding request state;
- Admin approval;
- privileged maker-checker;
- locations/schedules;
- device/geo/network controls;
- Security Control Registry;
- authorization version;
- Verigence JWT permissions;
- Admin/security audit.

These are authorization/governance controls, not authentication-provider features.

---

## 12. What Security must stop owning after Clerk cutover

Security MUST NOT continue building or exposing a parallel human credential product for ordinary/Platform human users:

- local password login;
- password policy engine;
- forgot/reset password flow;
- MFA seed/challenge management;
- email/phone verification;
- social login;
- enterprise SSO authentication;
- authentication-session recovery.

Any existing Increment-B local Platform credential flow is transitional implementation debt and must be disabled from the normal runtime path as part of Clerk cutover.

---

## 13. Clerk synchronization rules

### RULE-CLERK-001 — Do not mirror Clerk profile as authorization

Clerk metadata does not grant Tenant/Platform permissions unless a separately approved Security rule explicitly uses it.

### RULE-CLERK-002 — External identity uniqueness

A Clerk subject maps to one Security USER identity according to Security's existing external identity uniqueness rules.

An existing Clerk subject cannot be silently rebound to a second Security USER.

### RULE-CLERK-003 — Security is not dependent on Clerk for every authorization request

Security verifies Clerk identity at Security authentication/onboarding boundaries.

DI/WPM continue validating Security-issued Verigence JWTs locally and do not call Clerk per business request.

### RULE-CLERK-004 — Clerk webhooks are synchronization aids, not authorization authority

A future Clerk webhook integration may be used for lifecycle synchronization such as profile changes or disabled/deleted identities.

Webhook effects on Security status, memberships or sessions MUST be separately frozen before implementation.

This amendment does not invent those effects.

---

## 14. Cross-path and failure analysis

### 14.1 Clerk user exists, Security USER does not

Allowed during first access/onboarding/bootstrap.

Security may create the Security USER only through an approved flow that has authenticated Clerk identity and an explicit Security purpose (bootstrap claim, self-onboarding, invitation acceptance or approved user provisioning).

### 14.2 Security USER exists, Clerk mapping missing

No Clerk-authenticated access is granted until a valid approved identity binding is established.

### 14.3 Clerk account authenticates but Tenant membership is PENDING

Authentication succeeds; Tenant access remains denied/pending.

### 14.4 Clerk account authenticates but is suspended/ended in Security

Authentication succeeds at Clerk; Security authorization fails according to Security membership/principal state.

### 14.5 Clerk user is disabled/deleted

Security must reject future Clerk-authenticated requests once Clerk authentication no longer yields a valid session. Any proactive Security-side suspension/revocation driven by Clerk lifecycle events is deferred until webhook semantics are explicitly approved.

### 14.6 Wrong bootstrap Clerk account

Valid Clerk authentication is insufficient. Bootstrap claim is denied unless JWT `sub` equals the configured bootstrap Clerk user ID.

### 14.7 Bootstrap configuration remains after first claim

No new Super Admin is created. Existing ACTIVE Super Admin state closes bootstrap.

### 14.8 Bootstrap Clerk user ID changed after successful bootstrap

No automatic Platform assignment changes occur.

### 14.9 Multiple bootstrap requests race

The bootstrap transaction MUST serialize/check the no-ACTIVE-Super-Admin invariant so at most one first bootstrap assignment succeeds.

### 14.10 Clerk unavailable after user already has Security business JWT

Existing Security business JWT cryptographic validity remains governed by its existing `exp` and Security v1.3 semantics. This amendment does not introduce token introspection or instant revocation.

### 14.11 Clerk Organization/RBAC accidentally enabled

It MUST NOT be used as a Verigence authorization source. Security Tenant roles/memberships remain authoritative.

---

## 15. Revised implementation sequence

The previous sequence `F -> G` is paused.

Current sequence is:

```text
A  Admin persistence                          DONE
B  Local Super Admin + Tenant bootstrap       DONE / transitional auth debt
C  Module Catalogue + DI sync                 DONE
D  Groups + effective RBAC                    DONE
E  Tenant Role Admin APIs                     DONE
F  Human invitation + self-onboarding         DONE

CLERK INTEGRATION                              NOW
  -> Clerk configuration contract
  -> Clerk-backed Platform Super Admin bootstrap claim
  -> Clerk-backed Platform Admin authentication
  -> live Clerk self-onboarding identity
  -> live Clerk invitation-acceptance identity
  -> disable normal local Platform password login
  -> live Clerk JWT verification/E2E
  -> update tests and deployment secrets

G  Privileged maker-checker                   PAUSED UNTIL CLERK CUTOVER GREEN
H  Security Control Registry + Admin APIs
I  DI authorization alignment
J  deployed Security -> DI E2E
```

---

## 16. Clerk integration definition of done

The Clerk integration increment is not DONE until all applicable items pass:

1. Clerk configuration/secrets are deployment-controlled and not committed.
2. Security verifies live Clerk session JWTs using supported Clerk verification material.
3. authorized-party validation is configured for deployed clients where applicable.
4. first Super Admin is pre-created in Clerk and claimed exactly once using immutable Clerk user ID.
5. wrong Clerk user cannot bootstrap.
6. concurrent bootstrap cannot create multiple first Super Admins.
7. restart/configuration changes do not reopen bootstrap.
8. local Platform password login is disabled from the normal deployed runtime path.
9. Platform Super Admin authenticates through Clerk and retains only Security-owned Platform permissions.
10. self-onboarding succeeds from a live Clerk-authenticated identity and remains PENDING until Security Admin approval.
11. invitation acceptance binds the authenticated Clerk identity and preserves existing Security approval rules.
12. privileged roles remain pending maker-checker.
13. no Clerk Organization role/permission is used for authorization.
14. Security USER/external-identity uniqueness is preserved.
15. real Neon integration tests pass.
16. Security CI passes.
17. exact merge commit deploys to Railway DEV.
18. deployed live Clerk authentication -> Security control-plane/self-onboarding E2E passes.
19. tracker/status/recovery documentation is updated with exact evidence.

---

## 17. Test matrix additions

At minimum:

- valid Clerk bootstrap subject -> first Super Admin claim succeeds;
- valid Clerk JWT from wrong subject -> claim denied;
- second claim after existing Super Admin -> denied;
- concurrent first claims -> one succeeds;
- no Security plaintext/password material needed for Super Admin login after cutover;
- Clerk authenticated identity + no Security membership -> no Tenant business authorization;
- Clerk authenticated identity + PENDING membership -> no Tenant business authorization;
- Clerk authenticated identity + ACTIVE approved membership -> Security access flow continues normally;
- self-onboarding wrong Tenant token -> denied;
- self-onboarding valid Tenant token -> request PENDING, no self-assigned permissions;
- invitation acceptance cannot bind a Clerk subject already owned by another Security USER;
- Platform role does not imply Tenant/business permission;
- Clerk Organization role/permission has no effect on Security effective permissions;
- DI/WPM continue accepting only Security business JWTs.

---

## 18. Explicitly not decided here

This amendment does not invent:

- Clerk webhook-to-Security lifecycle mutation semantics;
- exact recent-MFA freshness threshold for sensitive Admin operations;
- exact Clerk frontend component/UI choice;
- Clerk Organization usage for non-authorization product features;
- machine authentication for SYSTEM/SERVICE_INTEGRATION actors;
- production SSO provider choice;
- device `BLOCKED` versus `REVOKED` semantics;
- complete SEC-032 activation prerequisites;
- cross-replica idempotency storage.

Any of these requires a separate explicit decision before implementation.

---

## 19. Final identity model

```text
                         CLERK
                 HUMAN AUTHENTICATION
       password / verification / MFA / SSO / session
                           |
                    Clerk session JWT
                           |
                           v
                  VERIGENCE SECURITY
                           |
          Clerk subject -> Security USER
                           |
        +------------------+------------------+
        |                                     |
 Platform roles                         Tenant memberships
        |                                     |
 Platform permissions                Groups / Tenant roles
                                              |
                                      Effective permissions
                                              |
                     +------------------------+------------------------+
                     |                                                 |
             Security Admin authorization                    Security business JWT
                                                                       |
                                                          +------------+------------+
                                                          |                         |
                                                         DI                        WPM
```

The governing rule is:

> **Clerk proves who the human is. Security decides what that human may do in Verigence.**
