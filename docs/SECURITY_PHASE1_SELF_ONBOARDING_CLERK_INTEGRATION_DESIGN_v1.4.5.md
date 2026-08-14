# Verigence Security — Phase 1 Self-Onboarding and Clerk Integration Design v1.4.5

**Status:** APPROVED IMPLEMENTATION AMENDMENT  
**Date:** 2026-08-14  
**Repository:** `verigence/verigence-security`  
**Applies to:** Phase 1 human self-onboarding, Clerk user creation, login identifier, mobile ownership, password transport, USER approval, and Clerk lifecycle integration.  
**Supersedes:** The invitation and post-sign-up `/bind` portions of `SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`.  
**Preserves:** Platform-global once-per-person onboarding, Security-owned USER status and authorization, no Tenant membership prerequisite, built-in Super Admin authority, and Clerk as credential/authentication provider.

---

## 1. Frozen Phase 1 decisions

1. Human onboarding is self-service after the person receives the Platform onboarding key from an authorized Security administrator.
2. Email address is the only user-facing sign-in identifier in Phase 1. There is no separate username/login ID.
3. Verigence generates its own internal UUID `user_id`; Clerk generates the immutable external `user_...` subject.
4. First name, last name, email, Indian mobile number and password are captured during sign-up.
5. Indian mobile number is stored and validated by Verigence only. Security MUST NOT send a dummy or real phone number to Clerk in Phase 1.
6. Email and normalized mobile number are globally unique in Verigence.
7. MFA is out of scope for Phase 1 and is deferred to Phase 2.
8. No Clerk invitation is created. No authenticated Clerk `/bind` step is required.
9. Security validates the onboarding key and duplicate identity data before any Clerk user is created.
10. Security calls Clerk Backend API to create the user only after all Verigence validation succeeds.
11. Security creates its local USER/external-identity/onboarding records only after Clerk confirms user creation.
12. A newly registered Security USER is `PENDING`; only an authorized Security Admin or Super Admin can set it to `ACTIVE`.
13. Tenant role/group/location/schedule assignment is separate from identity onboarding.

---

## 2. Phase 1 sign-up request

Public endpoint:

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <Platform onboarding key>
```

Request body:

```json
{
  "firstName": "Amit",
  "lastName": "Goyal",
  "email": "amit@example.com",
  "mobile": "+919876543210",
  "password": "<plaintext only for immediate Clerk forwarding>"
}
```

The UI may capture `confirmPassword`, but it is a client-side confirmation field and MUST NOT be persisted or forwarded as a separate Security API field.

There is no `tenantId`, Tenant code, role, Group, location, schedule, Clerk phone number, or separate username in this request.

---

## 3. Authoritative self-onboarding sequence

```text
User clicks Sign Up
  -> enters onboarding key + first name + last name + email + mobile + password
  -> UI POSTs once to Verigence Security
  -> Security validates onboarding is enabled and onboarding key is valid
  -> Security normalizes and validates email/mobile/names
  -> Security rejects if email already exists globally
  -> Security rejects if normalized mobile already exists globally
  -> Security calls Clerk POST /v1/users
  -> Clerk validates password and creates the authentication user
  -> Clerk returns immutable user_... ID
  -> Security transaction creates:
       security_principals = ACTIVE
       security.users = PENDING
       external_identities = CLERK / user_... / ACTIVE
       platform_user_onboarding_requests = PENDING_ADMIN_APPROVAL
       security event/audit evidence
  -> Security commits
  -> response: registration successful, pending administrator approval
```

The Security principal can remain `ACTIVE` while `security.users.status=PENDING`; all human access gates MUST still require the Security USER itself to be `ACTIVE`.

---

## 4. Identity and uniqueness model

### User-facing identity

```text
Sign-in ID = normalized email address
```

No Phase 1 username exists.

### Internal identity

```text
Verigence user_id = application-generated UUID
Clerk subject      = Clerk-generated immutable user_...
```

### Email normalization

Security stores and compares the lower-case trimmed email address. Email uniqueness is case-insensitive across all Security USERs.

### Mobile normalization

Phase 1 accepts Indian mobile numbers and stores one canonical form:

```text
+91XXXXXXXXXX
```

Equivalent inputs such as `9876543210`, `+91 98765 43210`, and `919876543210` normalize to the same canonical value. A canonical mobile may belong to only one Security USER.

Mobile is a Verigence profile/contact attribute. It is not sent to Clerk and is not a Phase 1 sign-in identifier.

---

## 5. Verigence -> Clerk user creation contract

Security calls Clerk Backend API over TLS using backend-only `CLERK_SECRET_KEY`:

```text
POST https://api.clerk.com/v1/users
Authorization: Bearer <CLERK_SECRET_KEY>
Content-Type: application/json
```

Payload:

```json
{
  "first_name": "Amit",
  "last_name": "Goyal",
  "email_address": ["amit@example.com"],
  "password": "<submitted password>"
}
```

Security MUST NOT send:

- `phone_number`;
- a dummy US phone number;
- `username`;
- Tenant identifiers or Tenant authorization;
- Security roles or permissions.

Clerk returns a User object. Security requires a non-empty immutable `id` beginning with `user_` before creating the local USER record.

Clerk Backend `createUser` treats email/phone values supplied through backend creation as verified. Phase 1 therefore does not claim a separate email-possession OTP verification step. If possession verification is required later, it must be introduced as an explicit approved flow rather than implied by this backend creation path.

---

## 6. Password boundary

Phase 1 intentionally uses one submit request to Verigence, followed by server-to-server Clerk user creation. Therefore Security transports the plaintext password transiently during registration.

Mandatory controls:

- HTTPS/TLS only from client to Security and Security to Clerk;
- password never stored in Security database, cache, file, queue, event, audit record, trace, metric label, or application log;
- password never echoed in API responses or exception messages;
- request-body logging/redaction must prevent password capture;
- Security does not authenticate passwords and does not maintain a password hash;
- Clerk remains the password validator and credential store;
- Security forwards the password only to Clerk user creation and releases it after the call.

Security MUST NOT call Clerk with `skip_password_checks=true` for ordinary onboarding.

Phase 1 relies on Clerk's configured password requirements. As of this design, Clerk Backend user creation requires a password of at least 8 characters and rejects known compromised passwords unless checks are deliberately bypassed; Verigence does not duplicate Clerk password-policy logic.

MFA is not enabled or required in Phase 1.

---

## 7. Failure and compensation rules

### Invalid/disabled onboarding key

Return access denial before any Clerk call and before any Security USER is created.

### Duplicate email or mobile

Return conflict before any Clerk call.

### Clerk rejects user creation

No Security USER is created. Return a sanitized registration error; do not expose `CLERK_SECRET_KEY`, password, or raw sensitive request data.

### Clerk creation succeeds but Security transaction fails

Security MUST attempt compensation:

```text
DELETE /v1/users/{clerk_user_id}
```

If compensation succeeds, no Clerk/Security orphan remains.

If compensation fails, Security still creates no usable local USER and returns failure. The orphaned Clerk identity is an operational reconciliation incident and has no Verigence access because Security has no ACTIVE USER mapping.

### Concurrent duplicate registration

Database uniqueness remains the final race-condition guard after the pre-check. If a uniqueness constraint rejects the Security transaction after Clerk creation, the same Clerk delete compensation rule applies.

---

## 8. Successful registration result

After Clerk creation and Security commit:

```text
Security USER status            = PENDING
Security principal status       = ACTIVE
CLERK external identity status  = ACTIVE
Onboarding request status       = PENDING_ADMIN_APPROVAL
Tenant authorization            = none
```

Response contract:

```json
{
  "onboardingRequestId": "<uuid>",
  "status": "PENDING_ADMIN_APPROVAL",
  "message": "Registration successful. Pending administrator approval."
}
```

The public response need not expose the internal Security `user_id` or Clerk `user_...` identifier.

---

## 9. Administrator approval

Existing Platform USER lifecycle administration remains authoritative:

```text
PATCH /security/v1/platform/users/{userId}/status
```

For a new self-onboarded USER:

```text
PENDING -> ACTIVE
```

Activation does not require a Tenant membership or Tenant role.

For a newly created PENDING Clerk user, Security does not need to unban Clerk merely to activate it because Phase 1 registration does not ban the Clerk account. Reactivation from `SUSPENDED` or `DISABLED` continues to require Clerk `unban` before Security returns to ACTIVE.

Deactivation remains:

```text
Security USER -> SUSPENDED / DISABLED / EXITED
  -> revoke Verigence access sessions
  -> Clerk POST /users/{user_id}/ban
```

Clerk ban revokes Clerk sessions and prevents further Clerk sign-in; Security USER status remains the primary Verigence authority.

---

## 10. Clerk Backend API surface for Phase 1

Required Security -> Clerk operations:

```text
POST   /v1/users                         create self-onboarded Clerk identity
DELETE /v1/users/{user_id}               compensate failed Security persistence
GET    /v1/users/{user_id}               lifecycle/profile reconciliation when needed
POST   /v1/users/{user_id}/ban           suspend/disable/exit enforcement
POST   /v1/users/{user_id}/unban         reactivation from suspended/disabled
```

Not used for Phase 1 onboarding:

```text
/v1/invitations
Clerk Organizations / Clerk RBAC
phone_number
MFA/TOTP/SMS
username
```

Interactive sign-in after Security activation continues to use Clerk authentication. Clerk produces the authenticated session/JWT, and Security resolves the Clerk `sub` to the global Security USER and requires USER status `ACTIVE` before issuing Verigence authorization.

---

## 11. Retired Phase 1 runtime surface

The following endpoint is retired from the active API because Clerk identity is created and mapped during the single self-onboarding request:

```text
POST /security/v1/onboarding/users/{requestId}/bind
```

Historical code/data may remain temporarily for migration evidence, but the endpoint MUST NOT appear in the active OpenAPI route table.

Clerk invitation creation is also retired from the active onboarding implementation.

---

## 12. Required implementation changes

v1.4.5 must:

1. replace invitation creation in the Clerk adapter with backend `create_user` and compensation `delete_user` support;
2. change `POST /security/v1/onboarding/users` request/response to this design;
3. remove the active `/bind` route;
4. add first/last-name persistence or equivalent canonical profile storage;
5. enforce canonical Indian mobile storage and global uniqueness;
6. create Security USER/mapping/request only after successful Clerk creation;
7. compensate Clerk if Security persistence fails;
8. keep new USER status `PENDING` until Security Admin approval;
9. keep mobile out of Clerk payloads;
10. keep MFA out of Phase 1;
11. update route-contract, unit and real Neon/PostgreSQL tests;
12. preserve all existing Tenant authorization and Super Admin behavior.

---

## 13. Acceptance tests

At minimum, automated evidence must prove:

1. invalid/disabled onboarding key produces no Clerk call and no Security USER;
2. duplicate email produces no Clerk call;
3. duplicate normalized Indian mobile produces no Clerk call;
4. correct request sends first name, last name, email and password to Clerk but no phone and no username;
5. Clerk user-creation failure produces no Security USER;
6. successful Clerk creation creates one PENDING Security USER and one CLERK external mapping;
7. resulting onboarding request is `PENDING_ADMIN_APPROVAL`;
8. password is never persisted in Security data/audit records;
9. Security DB failure after Clerk creation invokes Clerk delete compensation;
10. mobile uniqueness is enforced at database level against normalized stored values;
11. `/onboarding/users/{requestId}/bind` is absent from active OpenAPI;
12. Security Admin approval moves PENDING -> ACTIVE without requiring a Tenant membership;
13. suspend/disable still invokes Clerk ban and revokes Verigence sessions;
14. email-based precheck remains false until USER is ACTIVE;
15. Security CI and real Neon/PostgreSQL validation are green on the exact implementation head.

---

## 14. Final Phase 1 invariant

> **The person submits one Verigence self-registration form. Security validates the global onboarding key and global email/mobile uniqueness, Clerk creates the authentication identity, and only then Security creates a PENDING global USER. Email is the sign-in ID; mobile belongs only to Verigence; no invitation, Tenant onboarding, separate username, or MFA exists in Phase 1.**
