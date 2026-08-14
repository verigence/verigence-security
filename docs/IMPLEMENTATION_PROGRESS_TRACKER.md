# Verigence Security — Implementation Progress Tracker

**Status:** POINTER TO CURRENT VERSIONED TRACKER  
**Last updated:** 2026-08-14

The current canonical execution tracker is:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## Current governing model

- `SECURITY_PHASE1_SELF_ONBOARDING_CLERK_INTEGRATION_DESIGN_v1.4.5.md`: Phase 1 normal USER registration is single-submit self-onboarding. Email is the sign-in ID; Indian mobile is Verigence-only; no invitation, bind step, separate username or MFA is used.
- `SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`: human USER identity remains Platform-global and one-time; v1.4.5 supersedes only its invitation/bind registration sequence.
- `SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`: one built-in `platform.super_admin` role supplies full effective Security authority and inherits future ACTIVE permissions.
- `SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`: initial environment administrator is controlled setup data selected by immutable Clerk `user_...` ID.

Tenant membership is not a USER onboarding/access prerequisite. The same USER may receive Tenant-scoped authorization across multiple Tenants.

## Current promoted state

```text
Runtime code commit:       951a7694b31c195ccbde45d13346e0eea8ae9f14
Global USER onboarding:    DONE / DEPLOYED; Phase 1 registration sequence being amended by v1.4.5
Super Admin authority:     DONE / DEPLOYED
Initial Super Admin v1.4.4 DONE / PROVISIONED / DEPLOYED
Security CI:               GREEN on promoted baseline
Neon/PostgreSQL:           GREEN on promoted baseline
Railway DEV:               GREEN on promoted baseline
```

## Current workstream — v1.4.5

```text
User submits one form:
  onboarding key
  first name
  last name
  email
  Indian mobile
  password
       ↓
Security validates global onboarding key + email/mobile uniqueness
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

PR #54 implements this v1.4.5 correction and is under Security CI + real Neon/PostgreSQL validation.

DEV initial administrator remains:

```text
Clerk User ID:    user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Security user_id: 55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:             platform.super_admin
Status:           ACTIVE
```

## Current execution pointer

```text
PR #54 exact-head Security CI + Neon
   ↓
merge v1.4.5 to dev
   ↓
post-merge Security CI + Railway exact-digest health proof
   ↓
resume Increment G maker-checker
```

Do not reintroduce Clerk invitations, Tenant-scoped identity onboarding, Tenant membership for onboarding, a separate Phase 1 username, dummy Clerk phone numbers, or Phase 1 MFA.
