# Verigence Security — Global USER Onboarding and Tenant Authorization Design v1.4.2

**Status:** APPROVED IMPLEMENTATION AMENDMENT  
**Date:** 2026-08-14  
**Repository:** `verigence/verigence-security`  
**Applies to:** Human USER onboarding, Clerk lifecycle integration, USER status, Tenant authorization and USER access-session authorization versioning.  
**Supersedes:** Tenant-scoped human onboarding and Tenant-membership-as-access-prerequisite decisions in Admin Control Plane v1.4 and Clerk Identity Boundary v1.4.1 wherever they conflict with this amendment.  
**Does not supersede:** Clerk ownership of credentials/MFA/session authentication, Security ownership of authorization, Platform RBAC, Tenant RBAC, Groups, device/geo/network/schedule controls, module permission enforcement, machine identities or Security audit requirements.

---

## 1. Governing correction

Human USER onboarding is a **Platform-global, one-time lifecycle**.

A person is onboarded into Verigence once. The same Security `user_id` may later receive authorization in zero, one or many Tenants without repeating identity onboarding or creating another Clerk account.

```text
Person
  -> one Verigence Security USER
  -> one Clerk external identity mapping
  -> zero or more Tenant-scoped role/group/location/schedule assignments
```

Tenant membership is not a human identity prerequisite and is not required to grant Tenant authorization.

---

## 2. Non-negotiable ownership boundary

### RULE-GOU-001 — USER onboarding is global and once-per-person

Security MUST NOT require a person to onboard separately for each Tenant.

The onboarding workflow contains no `tenant_id` or Tenant code.

After a USER is ACTIVE, authorization administrators may assign that same USER roles, Groups, locations and schedules independently in multiple Tenants.

### RULE-GOU-002 — Security owns USER lifecycle status

`security.users.status` is authoritative for whether a human is allowed to use Verigence.

Canonical active lifecycle:

```text
PENDING -> ACTIVE -> SUSPENDED / DISABLED / EXITED
```

`INVITED` remains only for compatibility with historical v1.4 data and invitation records.

Only an authorized Security administrator may transition a normal onboarding USER to `ACTIVE`.

A Clerk account existing or successfully authenticating MUST NOT automatically activate a Security USER.

### RULE-GOU-003 — Clerk continues to own authentication

Clerk owns credentials, email verification, password/passkey, MFA, recovery, authentication sessions and Clerk session JWTs.

Security MUST NOT verify or store human passwords.

Security owns the decision whether an authenticated Clerk identity is allowed to obtain Verigence access.

---

## 3. Platform-global onboarding key

### RULE-GOU-KEY-001 — One Platform onboarding key

There is one Platform-global USER onboarding key, not one key per Tenant.

The key is a submission gate that allows a person to start the one-time Verigence onboarding flow. Possession of the key grants no Tenant role, permission or application access.

### RULE-GOU-KEY-002 — Human-shareable value

The onboarding key is intentionally human-shareable. Platform Super Admin / Platform Security Admin must be able to reveal and copy the current value on demand.

The implementation may generate a readable value such as:

```text
VGN-7K3M9Q2R
```

The exact random characters are implementation generated; no fixed production key exists in source.

### RULE-GOU-KEY-003 — Secure storage with controlled reveal

Because the value must remain retrievable, hash-only storage is insufficient.

Security stores:

- an Argon2id hash for validation;
- encrypted key material for authorized reveal;
- key version;
- ACTIVE/DISABLED status;
- creator/updater and timestamps.

The encryption key is deployment-secret material and MUST NOT be stored in the database or source repository.

### RULE-GOU-KEY-004 — Administrative controls

Authorized Platform administrators can:

- view/copy the current onboarding key;
- set a new human-shareable key;
- rotate to a new generated key;
- enable/disable onboarding;
- see version and update timestamps.

Rotation invalidates the old key immediately for new submissions.

---

## 4. Security-first onboarding sequence

### RULE-GOU-ONB-001 — Security validates before Clerk provisioning

Security MUST validate the Platform onboarding key before initiating Clerk user/invitation provisioning.

The flow is:

```text
1. Person submits:
     onboarding key
     display name
     email

2. Security validates:
     Platform onboarding key exists
     onboarding key status = ACTIVE
     supplied key matches stored Argon2id hash
     no existing Security USER uses the email

3. Security creates:
     security_principals actor_type=USER
     security.users status=PENDING
     platform_user_onboarding_request status=PENDING_CLERK

4. Security commits the pending state.

5. Security calls Clerk Backend API to create an application invitation.

6. Security stores Clerk invitation ID and marks request CLERK_INVITED.

7. Person completes Clerk sign-up / verification / credential / MFA flow.

8. Person presents an authenticated Clerk session JWT to Security binding endpoint.

9. Security verifies Clerk JWT and retrieves Clerk user profile.

10. Security requires Clerk email == pending Security onboarding email.

11. Security creates/resolves one CLERK external identity mapping.

12. Request becomes PENDING_ADMIN_APPROVAL.

13. Security keeps the Clerk account unable to continue Verigence sign-in until approval.

14. Security Admin reviews and explicitly activates the USER.

15. Security sets USER=ACTIVE and synchronizes Clerk to sign-in-enabled state.
```

### RULE-GOU-ONB-002 — No Tenant authorization during onboarding

The global onboarding request contains no Tenant role, Group, location, schedule or membership information.

Onboarding completion creates identity only.

Tenant authorization is a separate administrative operation after USER activation.

### RULE-GOU-ONB-003 — Duplicate identity protection

A Security USER email used by the initial email-based onboarding flow is globally unique case-insensitively.

A Clerk subject may map to only one Security USER.

Security MUST NOT silently merge or rebind an existing Clerk subject to another Security USER.

---

## 5. Security Admin approval

### RULE-GOU-APPROVAL-001

A newly bound Clerk USER remains `PENDING` until an authorized Platform Security Admin / Super Admin approves it.

Clerk authentication success is not approval.

### RULE-GOU-APPROVAL-002

Activation requires:

- Security USER exists;
- USER status is an allowed pre-active/reactivable state;
- active CLERK external identity exists;
- Clerk lifecycle synchronization succeeds;
- Security audit evidence is written.

After approval:

```text
security.users.status = ACTIVE
onboarding request = APPROVED
```

### RULE-GOU-APPROVAL-003

`EXITED` is terminal in the v1.4.2 implementation. Rehiring/reactivation semantics require a separate approved decision.

---

## 6. Subsequent authentication and USER status

### RULE-GOU-AUTH-001 — Pre-auth UI gate

The Security API exposes a minimal pre-authentication check that allows the future UI to ask whether an email corresponds to an ACTIVE Security USER with an active Clerk mapping before launching the normal Clerk sign-in experience.

The public response is only allow/deny and does not expose detailed lifecycle state.

This is a UX/traffic gate, not the final security boundary.

### RULE-GOU-AUTH-002 — Post-Clerk Security gate is mandatory

Every Security authentication/token-exchange boundary that consumes a Clerk JWT MUST still resolve the Clerk subject to a Security USER and require Security status to be ACTIVE.

A client bypassing the UI precheck cannot bypass Security status enforcement.

### RULE-GOU-AUTH-003 — Deactivation synchronizes to Clerk

When Security changes a USER to `SUSPENDED`, `DISABLED` or `EXITED`:

1. Security status changes first;
2. active Verigence USER access sessions are revoked;
3. Clerk user is banned so existing Clerk sessions are revoked and further Clerk sign-in is prevented;
4. if Clerk synchronization fails, Security remains fail-closed because USER status is already non-ACTIVE.

When Security reactivates an allowed non-terminal USER, Clerk is unbanned before Security commits ACTIVE state.

Security status remains the authority; Clerk ban/unban is lifecycle enforcement synchronization.

---

## 7. Tenant authorization after global onboarding

### RULE-GOU-TENANT-001 — No Tenant membership prerequisite

An ACTIVE Security USER may be assigned authorization in a Tenant directly.

Runtime authorization MUST NOT require a row in `security.tenant_memberships`.

Historical `tenant_memberships` rows/tables are retained until a separate data-retention migration is approved, but they are not an active authorization gate under v1.4.2.

### RULE-GOU-TENANT-002 — Access is assignment based

For a USER to receive a Tenant-scoped Verigence token, Security requires:

```text
Security Principal = ACTIVE
Security USER      = ACTIVE
Tenant             = ACTIVE
required role/group permissions exist
registered device controls pass
location controls pass
schedule controls pass
network controls pass
other active Security controls pass
```

No membership row is part of this decision.

### RULE-GOU-TENANT-003 — One USER, many Tenants

The same `user_id` may simultaneously have different authorization in different Tenants.

Example:

```text
USER U1
  Tenant A -> process_consultant
  Tenant B -> auditor
  Tenant C -> tenant.admin
```

Adding or removing Tenant authorization never creates a new Security USER or Clerk user.

### RULE-GOU-TENANT-004 — Tenant authorization version replaces membership version

Per-user/per-Tenant authorization invalidation is stored in:

```text
security.user_tenant_authorization_state
  user_id
  tenant_id
  authorization_version
  updated_at_utc
```

This table is authorization state only. It is not membership and grants no permission by itself.

Role, Group and other effective-authorization changes increment this version for the affected USER/Tenant scope.

---

## 8. Clerk Backend API boundary

The initial v1.4.2 onboarding implementation uses Clerk application invitations after Security key validation.

Security Backend API operations are restricted to:

- create application invitation;
- retrieve Clerk user profile for binding validation;
- ban user;
- unban user.

Security does not use Clerk Organizations/RBAC as authorization authority.

`CLERK_SECRET_KEY` is backend-only deployment secret material and MUST NOT be exposed to UI/mobile clients or persisted in Security tables.

---

## 9. Public and Platform API contract

### Platform onboarding-key administration

```text
GET    /security/v1/platform/user-onboarding/key
PUT    /security/v1/platform/user-onboarding/key
POST   /security/v1/platform/user-onboarding/key/rotate
DELETE /security/v1/platform/user-onboarding/key
```

Permissions:

```text
security.user_onboarding.read
security.user_onboarding.manage
```

### One-time public onboarding

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <Platform global key>
```

No Clerk session is required before this Security validation.

### Clerk identity binding

```text
POST /security/v1/onboarding/users/{requestId}/bind
Authorization: Bearer <Clerk session JWT>
```

### Global USER administration

```text
GET   /security/v1/platform/users
PATCH /security/v1/platform/users/{userId}/status
```

Permissions:

```text
security.user.read
security.user.manage
```

### Pre-authentication UI gate

```text
POST /security/v1/auth/precheck
```

Returns only:

```json
{"allowed": true}
```

or

```json
{"allowed": false}
```

---

## 10. Retired active-runtime APIs

The following v1.4 Tenant identity/onboarding surfaces are retired from the active route table:

- Tenant owner invitation that creates a new human identity;
- Tenant-scoped self-onboarding token management;
- Tenant-scoped human invitations;
- Tenant invitation acceptance for identity creation;
- `/onboarding/tenants/{tenantCode}/self-registrations`;
- Tenant self-onboarding request approval/rejection.

Their tables/code may remain temporarily as historical migration debt but MUST NOT be registered as active runtime endpoints.

Tenant administrators manage authorization of already-onboarded global USERs instead.

---

## 11. Database migration rules

v1.4.2 adds:

- `PENDING` Security USER lifecycle state;
- Platform-global onboarding key settings;
- Platform-global onboarding requests;
- global case-insensitive USER email uniqueness for the initial email flow;
- per-user/per-Tenant authorization state;
- USER access sessions without mandatory `membership_id`;
- Platform USER/onboarding permissions;
- Security controls for global onboarding and USER status.

The immutable v1.3 migration MUST NOT be edited.

The v1.4 Admin migration MUST NOT be rewritten to erase history.

v1.4.2 is an additive migration with explicit retirement of obsolete runtime controls.

---

## 12. Migration/compatibility policy

Existing `security.tenant_memberships`, `security.tenant_self_onboarding_settings`, `security.self_onboarding_requests` and `security.tenant_invitations` are not dropped automatically.

Reasons:

- historical audit/data may exist;
- previous DEV evidence must remain explainable;
- destructive cleanup requires a separate retention/migration decision.

Runtime code MUST ignore those objects for the global USER onboarding and ordinary Tenant authorization decision.

Existing membership authorization versions are copied forward into `user_tenant_authorization_state` during migration to preserve token-version continuity.

---

## 13. Failure analysis

### Wrong/disabled onboarding key

Security denies before any Clerk Backend API call or Security USER creation.

### Security USER already exists for email

Security rejects duplicate onboarding. Tenant assignment must use the existing USER.

### Clerk invitation call fails

Security leaves the USER `PENDING` and records onboarding request `CLERK_PROVISIONING_FAILED`. No access is granted.

### Clerk JWT binds with different email

Security denies identity binding.

### Clerk identity binds successfully

Security USER remains `PENDING`; the account is not authorized until Security Admin activation.

### Non-ACTIVE USER authenticates directly with Clerk

Security token exchange/access remains denied. Lifecycle synchronization also attempts to keep such Clerk users banned.

### USER has no roles in requested Tenant

Security denies with role/permission failure. No membership creation is attempted.

### USER has roles in multiple Tenants

Each Tenant is evaluated independently from the same global USER identity.

---

## 14. Acceptance tests required before DONE

The increment is DONE only when automated evidence proves at minimum:

1. Global onboarding key can be set, retrieved, rotated and disabled by an authorized Platform administrator.
2. Wrong/disabled key causes no Security USER and no Clerk invitation call.
3. Correct key creates one PENDING Security USER before Clerk invitation is initiated.
4. Duplicate email onboarding is rejected.
5. Clerk binding requires matching pending email and creates one CLERK mapping.
6. Binding does not activate the Security USER.
7. Security Admin activation changes USER to ACTIVE and unbans Clerk.
8. Suspend/disable revokes active Security sessions and invokes Clerk ban.
9. Precheck returns false for non-ACTIVE USER and true only for ACTIVE mapped USER.
10. ACTIVE USER can receive a Tenant role without `tenant_memberships` row.
11. The same USER can receive roles in two Tenants without re-onboarding.
12. Tenant RBAC authorization works without membership.
13. Runtime access session stores no membership ID and uses `user_tenant_authorization_state.authorization_version`.
14. Authorization changes bump only the affected USER/Tenant authorization version.
15. Legacy Tenant onboarding endpoints are absent from the active OpenAPI route table.
16. Security CI and real Neon/PostgreSQL integration pass on the exact implementation head.

---

## 15. Final boundary

```text
                         VERIGENCE SECURITY

Global identity/lifecycle                   Tenant authorization
-------------------------                   --------------------
USER onboarding once                        Roles
Global onboarding key                       Groups
USER PENDING/ACTIVE/etc.                    Permissions
Security Admin approval                     Locations
Clerk user mapping                          Schedules
Lifecycle ban/unban sync                    Devices
                                            Authorization version
           |                                      |
           +------------------+-------------------+
                              |
                              v
                    VERIGENCE ACCESS DECISION
                              |
                              v
                            CLERK
                    credentials / MFA / auth
```

The invariant is:

> **Identity onboarding happens once at Platform level. Tenant access is authorization assignment, not identity onboarding.**
