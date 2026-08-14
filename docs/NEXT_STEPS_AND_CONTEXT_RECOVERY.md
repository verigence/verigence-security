# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4 + Phase 1 Self-Onboarding/Clerk Integration v1.4.5  
**Last updated:** 2026-08-14

## 1. Governing recovery rule

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md`;
3. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`;
4. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`;
5. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` for unchanged global lifecycle/Tenant authorization rules;
6. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
7. `docs/INITIAL_SUPER_ADMIN_PROVISIONING_TEST_REPORT_v1.4.4.md`;
8. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`;
9. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
10. `docs/IMPLEMENTATION_STATUS.md`;
11. current `dev`, open Security PRs and CI/Railway state.

## 2. Invariants that must survive every reset

```text
Normal human onboarding  = Platform-global, once per person
Phase 1 registration     = self-onboarding with one Platform onboarding key
Sign-in identifier       = email; no separate username
Indian mobile            = Verigence-only; never sent to Clerk in Phase 1
MFA                      = not Phase 1; introduce in Phase 2
Clerk                     = credential/authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Platform Super Admin      = built-in role with full Security authority
Initial administrator     = operator-selected Clerk user_... provisioned as setup data
```

Do not reconstruct Tenant-scoped identity onboarding, Clerk invitations, the `/bind` flow, a dummy Clerk phone number, or a Phase 1 MFA requirement.

## 3. Phase 1 self-onboarding v1.4.5

The person receives the current Platform onboarding key from an authorized Security administrator and submits one registration form:

```text
onboarding key
first name
last name
email
Indian mobile
password
```

The authoritative order is:

```text
Security validates onboarding key
   ↓
Security checks email uniqueness + normalized Indian mobile uniqueness
   ↓
Security calls Clerk POST /v1/users
   first_name + last_name + email_address + password only
   ↓
Clerk returns immutable user_...
   ↓
Security transaction creates:
   principal ACTIVE
   USER PENDING
   CLERK external identity ACTIVE
   onboarding request PENDING_ADMIN_APPROVAL
   ↓
user sees pending-approval response
   ↓
Security Admin/Super Admin later changes PENDING -> ACTIVE
```

Mobile is stored only in Security in canonical `+91XXXXXXXXXX` form. No real or dummy phone number is passed to Clerk.

Password is transient registration transport only. It must never be persisted, hashed, logged, audited, traced or returned by Security. Clerk remains credential validator/store/authenticator.

If Clerk creation succeeds and Security persistence then fails, Security attempts `DELETE /v1/users/{user_id}` compensation. If that delete also fails, no local usable Security USER is committed, so Verigence access remains fail-closed and the Clerk orphan requires operational reconciliation.

## 4. Current promoted runtime baseline

```text
DEV runtime commit: 951a7694b31c195ccbde45d13346e0eea8ae9f14
```

DEV initial Super Admin:

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
Status:            ACTIVE
```

## 5. Current workstream

**NOW:** PR #54 — Phase 1 self-onboarding and Clerk integration v1.4.5.

Required sequence:

```text
feature/phase1-self-onboarding-clerk-v1.4.5
   ↓
Security CI + real Neon/PostgreSQL
   ↓
merge PR #54 to dev
   ↓
exact-commit Security CI
   ↓
immutable GHCR image -> Railway DEV
   ↓
readiness + liveness + correlation
   ↓
record v1.4.5 evidence
   ↓
resume Increment G maker-checker
```

The active Phase 1 onboarding API is one `POST /security/v1/onboarding/users` request with `X-Onboarding-Key`. `/security/v1/onboarding/users/{requestId}/bind` is retired from active OpenAPI.

## 6. Tenant authorization rule

Normal people are onboarded once as global Security USERs. The same `user_id` can receive independent roles, Groups, locations and schedules in multiple Tenants without another onboarding event or Tenant membership requirement.

## 7. Promotion discipline

```text
feature/*
   ↓ Security CI + applicable real Neon/PostgreSQL
  dev
   ↓ exact-commit Security CI
immutable GHCR image -> Railway DEV
   ↓ readiness + liveness + correlation
```

Do not resume Increment G until v1.4.5 is merged and deployed green.
