# Verigence Security — Implementation Progress Tracker v1.4.2

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted runtime code commit:** `7765e72a6078a15981cffb42c0d7e3bdbdc269de` (v1.4.5 until v1.4.6 promotion completes)  
**Date:** 2026-08-15

## 1. Implementation authorities

Read/apply in this order when decisions conflict:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_PHASE1_CLERK_EMAIL_OTP_DESIGN_v1.4.6.md` for active Phase 1 human self-registration;
3. `docs/CLERK_EMAIL_OTP_INTEGRATION_CONTRACT_v1.4.6.md` for the concrete Verigence <-> Clerk integration;
4. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md` for fresh-environment initial administrator provisioning;
5. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md` for built-in Super Admin authority;
6. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for unchanged global USER lifecycle and Tenant authorization rules;
7. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk authentication ownership;
8. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin Control Plane scope;
9. Security v1.3 normative artifacts for unchanged runtime scope;
10. this tracker for current execution/evidence.

`SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md` and its test report remain historical evidence. Their backend Clerk `POST /v1/users` signup path is superseded by v1.4.6.

## 2. Executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Static/design, compile, Ruff, Mypy, tests, build and dependency checks enforced |
| Phase 2 Neon DEV | GREEN ON v1.4.6 FEATURE | Real PostgreSQL v1.4.6 acceptance + historical regressions green |
| Phase 3 Railway DEV | v1.4.5 DEPLOYED / v1.4.6 PENDING | Merge and exact-commit promotion still required |
| Admin Control Plane A–F | DONE / HISTORICAL F IDENTITY SUPERSEDED | A–E active; F Tenant identity onboarding superseded by global onboarding |
| Clerk identity boundary v1.4.1 | BACKEND IMPLEMENTED / DEPLOYED | Clerk remains the human credential/authentication provider |
| Global USER onboarding v1.4.2 | DONE / FLOW AMENDED | USER onboarding remains Platform-global and one-time |
| Phase 1 self-onboarding v1.4.5 | HISTORICAL DEPLOYED BASELINE | Backend Clerk create-user path superseded by v1.4.6 |
| Clerk email OTP onboarding v1.4.6 | FEATURE GATES GREEN / PROMOTION PENDING | Password + OTP owned by Clerk; Security creates USER only after verified email |
| Built-in Platform Super Admin authority v1.4.3 | DONE / DEPLOYED | Full current/future permission authority and Tenant provisioning authority validated |
| Initial Super Admin system provisioning v1.4.4 | DONE / PROVISIONED / DEPLOYED | Selected Clerk identity is ACTIVE Security Super Admin in DEV |
| Increment G maker-checker | COMPLETED / MERGED | PR #58 merged to Security `dev`; privileged-access maker-checker implemented |
| Increment H Control Registry/runtime Admin APIs | TRACKED SEPARATELY | Existing H work remains governed by its own branch/PR status; do not infer completion from I |
| Increment I DI authorization alignment | DONE / MERGED | DI PR #1 merged; canonical actor, Tenant and permission alignment completed |
| Increment J Security -> DI deployed E2E | DEFERRED / NOT STARTED | Resume later only on explicit user direction; final deployed integration proof remains outstanding |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

## 3. Frozen Phase 1 identity/onboarding model

```text
Normal human onboarding  = Platform-global, one time per person
Phase 1 registration     = self-onboarding with shared Platform onboarding key
Sign-in identifier       = email address; no separate username
Indian mobile            = Verigence-only; never sent to Clerk in Phase 1
Password                 = sent client-to-Clerk only; never to Security
Email OTP                = generated/delivered/verified by Clerk
Security USER creation   = only after exact pre-authorized Clerk email is verified
MFA                      = deferred to Phase 2
Tenant access             = authorization assignment, not identity onboarding
Clerk                     = credential/authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
```

The same ACTIVE global Security USER may receive different Tenant-scoped roles/groups/locations/schedules in multiple Tenants without another onboarding event.

## 4. Phase 1 Clerk email OTP onboarding v1.4.6 — FEATURE VALIDATED / PROMOTION PENDING

Authoritative registration sequence:

```text
UI -> Security start:
  onboarding key + first name + last name + email + Indian mobile
  -> validate key and global email/mobile uniqueness
  -> create 30-minute signupAttemptId
  -> NO Security USER exists

UI -> Clerk:
  email + password
  -> Clerk sends email OTP
  -> user enters OTP to Clerk
  -> Clerk verifies email and finalizes session

UI -> Security complete:
  signupAttemptId + Clerk session JWT
  -> Security validates Clerk JWT
  -> Security GETs Clerk user and requires exact email verification.status=verified
  -> Security creates global USER=PENDING + CLERK mapping + PENDING_ADMIN_APPROVAL
  -> user receives pending-approval response
  -> Security Admin/Super Admin later activates USER
```

Active API contract:

```text
POST /security/v1/onboarding/users
X-Onboarding-Key: <global key>
body: firstName, lastName, email, mobile
response: HTTP 202 + signupAttemptId + CLERK_EMAIL_VERIFICATION_REQUIRED + expiresAt

POST /security/v1/onboarding/users/{signupAttemptId}/complete
Authorization: Bearer <Clerk session JWT>
response: HTTP 201 + PENDING_ADMIN_APPROVAL
```

Implementation includes:

- additive migration `0007_clerk_email_otp_onboarding_v1.4.6.sql`;
- `security.platform_user_signup_attempts` with 30-minute pre-authorization;
- exact email/mobile duplicate gating before Clerk signup;
- Clerk JWT completion gate;
- Clerk Backend `GET /v1/users/{user_id}` exact verified-email check;
- names-only Clerk profile synchronization;
- no active Security password transport;
- no Clerk phone/username/Tenant/RBAC payload;
- dedicated unit and real Neon/PostgreSQL acceptance tests.

## 5. v1.4.6 feature validation evidence

```text
Exact feature head:       e9cf8326b1e0a49b164dac028a218b2f016eb77d
Security CI #186:         PASS
Neon/PostgreSQL #171:     PASS
PR #56:                   OPEN / DRAFT / NOT YET MERGED
Post-merge Security CI:   PENDING
Railway DEV:              PENDING
Live Clerk OTP E2E:       PENDING
```

Validated acceptance includes:

- invalid onboarding key -> no signup attempt/no USER;
- valid start -> short-lived signup attempt and still no USER;
- duplicate live email/mobile attempt -> denied;
- unverified Clerk email -> completion denied and no USER;
- verified exact Clerk email -> exactly one Security USER=PENDING + CLERK mapping;
- onboarding request -> PENDING_ADMIN_APPROVAL;
- completed attempt -> cannot replay;
- PENDING USER precheck remains false;
- v1.4.5 active backend-create `register()` path is retired;
- historical global USER/cross-Tenant authorization remains green;
- Platform Super Admin regression remains green;
- retained Phase 5 PostgreSQL administration suite remains green.

## 6. Live E2E requirement before closure

After v1.4.6 is promoted to Railway DEV, perform one real Clerk OTP registration using a unique Gmail alias routed to `gigsinopensource@gmail.com`.

The test must:
1. pre-authorize via deployed Security API;
2. have Clerk send the email OTP;
3. have the user supply the OTP to Clerk, never Security;
4. finalize Clerk session;
5. complete Security registration to USER=PENDING;
6. verify Clerk email `verification.status=verified` and Security `PENDING_ADMIN_APPROVAL`;
7. **pause before deletion so the user can inspect the Clerk Dashboard user**;
8. only after explicit user confirmation, delete Clerk and all associated Security signup/onboarding/audit/identity/principal rows;
9. prove zero residual records.

## 7. Initial DEV Super Admin — COMPLETED

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Platform role:     platform.super_admin
```

Verified Security principal/USER/CLERK mapping/Super Admin role are ACTIVE with zero missing ACTIVE permissions.

## 8. Increment I — COMPLETED

Increment I aligned DI authorization with the Security contract and is complete via merged DI PR #1.

Recorded completion scope:

```text
canonical actor types: USER / SYSTEM / SERVICE_INTEGRATION
missing or unknown actor_type: fail closed
Tenant path isolation: enforced
canonical DI read permissions: enforced
Security JWT/JWKS is the DI authorization trust boundary
wrong Tenant: 403
missing required permission: 403
```

Increment I is closed. Do not reopen or modify DI as part of Increment J unless the explicit approval gate below is satisfied.

## 9. Increment J — DEFERRED / RESUME LATER

Increment J is the final deployed Security -> DI integration proof. It is **not started and not complete**.

When explicitly resumed, the acceptance target is:

1. obtain a JWT issued by the deployed Security service;
2. prove DI validates that JWT through the Security JWKS trust boundary;
3. prove an operation succeeds with the required canonical `di.*` permission;
4. prove the same operation returns HTTP 403 without that permission;
5. prove a cross-Tenant attempt returns HTTP 403.

No completion claim may be made until deployed evidence exists.

### Mandatory DI change-approval gate

`verigence/verigence-di` is a protected work boundary for this Security workstream.

**No DI file, branch, workflow, configuration, documentation or runtime code may be changed without explicit user approval first.**

If Increment J reveals that a DI change is required, stop and present the user with:

```text
Repository: verigence/verigence-di
Exact file(s) proposed for change: <path(s)>
Why each file needs to change: <reason>
Exact intended change: <summary>
Expected effect/risk: <impact>
```

Only after the user explicitly approves that proposal may the DI change be made. Reading/inspection of DI is allowed for diagnosis; write operations are not.

## 10. Current execution pointer

```text
Increment I DI authorization alignment    DONE
       ↓
Increment J Security -> DI deployed E2E  DEFERRED / NOT STARTED
       ↓
Resume J only on explicit user direction
       ↓
If DI modification appears necessary:
STOP -> disclose exact file(s) + reason + intended change -> obtain explicit approval -> only then modify
```

Do not reintroduce Clerk invitations, Tenant-scoped human onboarding, Tenant membership for USER onboarding, a separate Phase 1 username, dummy Clerk phone numbers, backend Clerk create-user as normal signup, Security-proxied passwords, or Phase 1 MFA.
