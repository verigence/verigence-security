# Verigence Security — Implementation Progress Tracker

**Status:** POINTER TO CURRENT VERSIONED TRACKER  
**Last updated:** 2026-08-14

The current canonical execution tracker is:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

## Current governing model

`docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` governs normal human USER onboarding:

> **Human USER onboarding is Platform-global and one-time. Tenant access is authorization assignment, not identity onboarding.**

`docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md` governs Super Admin authority:

> **The built-in Platform Super Admin can initialize and administer the entire Security platform without another administrator provisioning additional roles first.**

`docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md` governs fresh-environment initial administrator creation:

> **The operator-selected immutable Clerk User ID is provisioned once as the initial global Security USER and built-in `platform.super_admin`; a manual first-user claim is not required.**

Therefore:

- there is one global Security USER per person;
- normal USER onboarding remains one-time and Platform-global;
- Tenant membership is not a USER access prerequisite;
- the same USER may receive Tenant-scoped authorization in multiple Tenants;
- `platform.super_admin` owns every ACTIVE Security permission and inherits future ACTIVE permissions automatically;
- the initial administrator is selected by immutable Clerk `user_...` environment configuration;
- initial system provisioning creates no Tenant membership, Tenant role or local password credential.

## Promoted baseline

```text
DEV commit:             b3c9994c420a261ef55ad402f1d8219651eebdb7
Global USER onboarding: DONE / DEPLOYED
Super Admin authority:  DONE / DEPLOYED
Security CI:            GREEN
Neon/PostgreSQL:        GREEN
Railway DEV:            GREEN
```

## Current execution pointer

```text
feature/super-admin-system-provisioning-v1.4.4
   ↓
Security CI + Neon regression
   ↓
merge to dev with controlled provisioning marker
   ↓
seed selected Clerk user_... as initial Security platform.super_admin
   ↓
verify ACTIVE mapping + full permission coverage
   ↓
normal Clerk authentication / Security Platform Admin login
   ↓
resume Increment G maker-checker
```

Increment G remains paused until the initial DEV Super Admin is provisioned and its normal Clerk -> Security login is proven.
