# Verigence Security Self-Onboarding Design v1.4

**Status:** APPROVED FOR IMPLEMENTATION  
**Date:** 2026-08-13  
**Extends:** `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` and `docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md`  
**Supersedes:** no Security v1.3 normative artifact.

## 1. Purpose

Invitation-led onboarding remains supported, but it is not the only onboarding path.

A Tenant may allow **self-onboarding**. The Platform Super Admin sets a Tenant-specific onboarding token when the Tenant is created or later rotates it. A person who knows that token may submit a self-onboarding request, but the request does **not** become an ACTIVE Tenant membership until an authorized Tenant Admin approves it.

The onboarding token protects the public self-registration API. Human Admin approval remains the final authorization boundary.

## 2. Security model

The onboarding token is **not** the user's identity credential.

The two checks serve different purposes:

```text
External identity authentication
        |
        | proves who the person is
        v
Tenant onboarding token
        |
        | proves possession of Tenant self-onboarding secret
        v
PENDING Tenant membership/request
        |
        | Tenant Admin reviews
        v
APPROVED -> ACTIVE membership
```

A token alone can never produce an ACTIVE Tenant membership.

## 3. Governing rules

### RULE-SELF-001 — Tenant-scoped token

Every onboarding token belongs to exactly one Tenant. It cannot be used to join another Tenant.

### RULE-SELF-002 — Token set by Platform Super Admin

In the first release only Platform Super Admin may create, rotate, disable or replace the Tenant self-onboarding token.

### RULE-SELF-003 — Token never stored in plaintext

The supplied token is hashed with Argon2id before persistence.

The plaintext value MUST NOT be stored in:

- Git;
- database columns;
- logs;
- audit before/after JSON;
- error messages;
- tracing data;
- container images.

The token is shown/known only at the time the Super Admin supplies it to the system.

### RULE-SELF-004 — Self-onboarding must also be enabled

A valid token is insufficient if effective control `admin.self_onboarding` is OFF for the Tenant.

Both are required:

```text
self-onboarding control = enabled
AND
presented Tenant token = valid
```

### RULE-SELF-005 — Identity authentication remains required

The caller must be authenticated through the configured USER identity provider before Security accepts the self-onboarding request.

For current DEV/live USER architecture this is the existing external-identity boundary (for example Clerk). The onboarding token does not replace identity verification.

### RULE-SELF-006 — Pending only

Successful self-registration creates/reuses the Security USER identity as appropriate and creates a Tenant-scoped onboarding request/membership in a non-effective pending state.

It does not grant Tenant access, roles, Groups, locations, schedules or module permissions.

### RULE-SELF-007 — Admin approval mandatory

A self-onboarded user's Tenant membership becomes ACTIVE only after an authorized Tenant Admin approves the request.

This approval cannot be disabled by `admin.self_onboarding` or by possession of the onboarding token.

### RULE-SELF-008 — User does not self-select authorization

The self-registration request cannot choose effective roles, Groups, permissions, locations or schedules.

Those are assigned/reviewed by the Tenant Admin during approval.

The user may provide non-authorization profile information permitted by the request contract, such as display name/contact information.

### RULE-SELF-009 — Privileged roles retain maker-checker

If the approving Admin assigns a privileged role defined by the Admin Control Plane design, the privileged-access maker-checker rule still applies when `admin.privileged_access_approval` is enabled.

Self-onboarding never bypasses privileged-role approval.

### RULE-SELF-010 — Duplicate/replay safe

The same authenticated external identity must not create multiple effective memberships for the same Tenant.

If a PENDING self-onboarding request already exists for the same Tenant/user, the API returns that existing pending state rather than creating parallel requests.

If the user already has an ACTIVE membership, self-onboarding does not create another membership or downgrade it.

### RULE-SELF-011 — Token rotation is immediate for future submissions

Rotating/disabling the Tenant token invalidates the previous token for all future self-onboarding submissions.

Existing PENDING requests remain pending and must still be approved/rejected by Admin; token rotation does not silently approve or delete them.

### RULE-SELF-012 — Public endpoint is rate-limited and audited

The self-onboarding endpoint must be rate-limited by the deployment/API layer and Security must audit successful, denied and invalid-token attempts by correlation ID without recording the submitted token.

No fixed rate-limit number is invented by this design; the operational threshold must be explicit environment/platform configuration.

## 4. Tenant creation contract

Direct Tenant creation remains Platform Super Admin controlled.

The Tenant create API may configure self-onboarding in the same control-plane transaction:

```text
POST /security/v1/platform/tenants
```

Conceptual request extension:

```json
{
  "tenantCode": "abc-motors",
  "tenantName": "ABC Motors",
  "selfOnboarding": {
    "enabled": true,
    "token": "<operator-supplied-secret>"
  }
}
```

Rules:

- `token` is write-only and never returned;
- if `enabled=true`, a token is required;
- the token is immediately Argon2id-hashed;
- Tenant control override for `admin.self_onboarding` is set to `ENABLED`;
- if self-onboarding is omitted/disabled, no usable onboarding secret is created automatically;
- Tenant still starts `CONFIGURING` under the Admin Control Plane design.

A separate rotation endpoint is also required:

```text
PUT    /security/v1/platform/tenants/{tenantId}/self-onboarding-token
DELETE /security/v1/platform/tenants/{tenantId}/self-onboarding-token
```

Both require Platform Super Admin authorization and structured Admin audit.

## 5. Self-registration API

Target public/authenticated endpoint:

```text
POST /security/v1/onboarding/tenants/{tenantCode}/self-registrations
```

Authentication/context:

```text
Authorization: Bearer <external USER identity token>
X-Onboarding-Token: <Tenant onboarding token>
X-Correlation-ID: <caller correlation id>
```

The onboarding token header is treated as sensitive and must be redacted from request logs/traces.

Conceptual body:

```json
{
  "displayName": "User Name"
}
```

The body deliberately contains no role/group/permission/location selection.

### Validation order

1. validate/generate correlation ID;
2. authenticate external USER identity;
3. resolve Tenant by `tenantCode`;
4. verify effective `admin.self_onboarding=true`;
5. verify Tenant onboarding token hash;
6. resolve/create the Security USER identity mapping safely;
7. reject/reuse duplicate Tenant membership/request as defined above;
8. persist a PENDING self-onboarding request and PENDING Tenant membership;
9. emit audit evidence;
10. return PENDING status only.

Invalid token, disabled self-onboarding, invalid Tenant, or invalid identity must fail closed without revealing whether a particular account already exists.

## 6. Admin approval API

Tenant Admin review endpoints:

```text
GET  /security/v1/admin/tenants/{tenantId}/self-onboarding-requests
GET  /security/v1/admin/tenants/{tenantId}/self-onboarding-requests/{requestId}
POST /security/v1/admin/tenants/{tenantId}/self-onboarding-requests/{requestId}/approve
POST /security/v1/admin/tenants/{tenantId}/self-onboarding-requests/{requestId}/reject
```

Permissions:

```text
list/get: security.member.read
approve/reject: security.member.approve
```

Approval request may assign the approved Tenant context:

```json
{
  "roleIds": ["..."],
  "groupIds": ["..."],
  "locationAssignments": [
    {
      "locationId": "...",
      "scheduleId": "..."
    }
  ]
}
```

All referenced objects must belong to the same Tenant and be valid/effective.

If privileged roles are requested, maker-checker is applied according to the Admin Control Plane design.

## 7. State model

Use a dedicated onboarding request record; do not overload invitation semantics.

```text
SELF_ONBOARDING_REQUEST

PENDING_ADMIN_APPROVAL
        |
        +--> APPROVED
        |
        +--> REJECTED
        |
        +--> CANCELLED
```

The Tenant membership remains `PENDING` until approval and becomes `ACTIVE` only when the required approval path completes.

For a newly authenticated global USER, `security.users` represents the identity; Tenant access is controlled by the Tenant membership/request state. A user who already belongs to another Tenant is not globally downgraded while waiting for approval in this Tenant.

## 8. Database extension

### `security.tenant_self_onboarding_settings`

```text
tenant_id                    PK/FK -> security.tenants
token_hash                   text NOT NULL
token_version                bigint >= 1
status                       ACTIVE | DISABLED
created_by_user_id           FK -> security.users
created_at_utc               timestamptz
updated_by_user_id           FK -> security.users
updated_at_utc               timestamptz
```

No plaintext token column exists.

### `security.self_onboarding_requests`

```text
self_onboarding_request_id   uuid PK
tenant_id                    FK -> security.tenants
user_id                      FK -> security.users
external_identity_id         FK -> security.external_identities
status                       PENDING_ADMIN_APPROVAL | APPROVED | REJECTED | CANCELLED
submitted_at_utc             timestamptz
submitted_source_ip          inet
reviewed_by_user_id          nullable FK -> security.users
reviewed_at_utc              nullable timestamptz
review_reason                nullable text
correlation_id               uuid
UNIQUE (tenant_id, user_id) for open/effective request semantics
```

The final DDL must enforce one open/effective Tenant membership path without editing the immutable v1.3 baseline migration.

## 9. Invitation and self-onboarding coexistence

Both onboarding channels remain supported:

```text
Invitation-led
Admin initiates -> recipient accepts -> membership becomes effective per approval rules

Self-onboarding
User initiates with Tenant token -> Admin approves -> membership becomes effective per approval rules
```

They converge on the same Security USER, Tenant membership, RBAC, Group and location assignment model.

There is no separate authorization engine for self-onboarded users.

## 10. Acceptance tests

Implementation is complete only when tests prove:

1. correct token + authenticated identity creates only PENDING membership/request;
2. wrong token creates no membership;
3. valid token while `admin.self_onboarding=OFF` is denied;
4. token from Tenant A cannot join Tenant B;
5. plaintext token never appears in DB/log/audit response;
6. token rotation invalidates old token;
7. duplicate submission reuses pending state;
8. ACTIVE member cannot create another membership through self-onboarding;
9. user cannot request/assign their own roles/groups/locations;
10. Admin approval activates the membership with only approved Tenant-scoped assignments;
11. rejection leaves no effective Tenant access;
12. privileged role assignment still follows maker-checker when enabled;
13. cross-Tenant Admin approval is denied;
14. deployed Railway DEV E2E proves identity -> token -> PENDING -> Admin approval -> Security access-session issuance.
