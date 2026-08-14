# Verigence Security — Implementation Progress Tracker

**Status:** POINTER TO CURRENT VERSIONED TRACKER  
**Last updated:** 2026-08-14

The current canonical execution tracker is:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## Current governing model

- `SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md`: Phase 1 normal USER registration is single-submit self-onboarding. Email is the sign-in ID; Indian mobile is Verigence-only; no invitation, bind step, separate username or MFA is used.
- `SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`: human USER identity remains Platform-global and one-time; v1.4.5 supersedes its invitation/bind registration sequence.
- `SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`: one built-in `platform.super_admin` role supplies full effective Security authority and inherits future ACTIVE permissions.
- `SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`: initial environment administrator is controlled setup data selected by immutable Clerk `user_...` ID.

Tenant membership is not a USER onboarding/access prerequisite. The same USER may receive Tenant-scoped authorization across multiple Tenants.

## Current promoted state

```text
Runtime code commit:       7765e72a6078a15981cffb42c0d7e3bdbdc269de
Phase 1 self-onboarding:   DONE / DEPLOYED
Global USER onboarding:    DONE / DEPLOYED / registration flow amended by v1.4.5
Super Admin authority:     DONE / DEPLOYED
Initial Super Admin v1.4.4 DONE / PROVISIONED / DEPLOYED
Feature Security CI:       31779990307 — PASS
Feature Neon/PostgreSQL:   31779986825 — PASS
Post-merge Security CI:    31780116228 — PASS
Railway DEV:               31780116188 — PASS
readiness/liveness/correlation: PASS
```

## Frozen Phase 1 registration flow

```text
User submits:
  onboarding key
  first name
  last name
  email
  Indian mobile
  password
       ↓
Security validates onboarding key + email/mobile uniqueness
       ↓
Security -> Clerk POST /v1/users
  first_name + last_name + email_address + password
  NO phone
  NO username
       ↓
Clerk returns user_...
       ↓
Security creates USER=PENDING + CLERK mapping + PENDING_ADMIN_APPROVAL
       ↓
Security Admin/Super Admin later activates USER
```

Password is transient registration transport only and is never stored, hashed, logged or audited by Security. MFA is deferred to Phase 2.

Detailed v1.4.5 evidence:

```text
docs/PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_TEST_REPORT_v1.4.5.md
```

DEV initial administrator remains:

```text
Clerk User ID:    user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Security user_id: 55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:             platform.super_admin
Status:           ACTIVE
```

## Current execution pointer

```text
Phase 1 self-onboarding v1.4.5  DONE / DEPLOYED
   ↓
Increment G maker-checker       NEXT
```

Do not reintroduce Clerk invitations, Tenant-scoped identity onboarding, Tenant membership for onboarding, a separate Phase 1 username, dummy Clerk phone numbers, or Phase 1 MFA.
