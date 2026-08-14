# Verigence Security — Implementation Progress Tracker

**Status:** POINTER TO CURRENT VERSIONED TRACKER  
**Last updated:** 2026-08-14

The current canonical execution tracker is:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

Do not use older execution pointers in this file from repository history to determine the next implementation
increment.

## Current governing correction

`docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md` freezes the current model:

> **Human USER onboarding is Platform-global and one-time. Tenant access is authorization assignment, not
> identity onboarding.**

Therefore:

- there is one global Security USER per person;
- there is one Platform-global onboarding key;
- Security validates the onboarding key before Clerk provisioning;
- Security USER remains PENDING until Security Admin activation;
- Tenant membership is not a USER access prerequisite;
- the same active USER may receive roles/groups/locations/schedules in multiple Tenants;
- per-user/per-Tenant authorization versioning uses `user_tenant_authorization_state`;
- Tenant-scoped identity onboarding routes from historical Increment F are retired from active runtime.

## Historical trackers/evidence

Use these only for the implementation state they record:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.1.md
docs/CLERK_IDENTITY_INTEGRATION_TEST_REPORT_v1.4.1.md
docs/ADMIN_CONTROL_PLANE_INCREMENT_A_VALIDATION.md
docs/ADMIN_CONTROL_PLANE_INCREMENT_B_VALIDATION.md
```

The v1.4.1 tracker records the historical Admin Control Plane and Clerk work before the v1.4.2 architecture
correction. It is not the current execution authority for human onboarding or Tenant membership.

## Current execution pointer

```text
feature/global-user-onboarding-v1.4.2
   ↓
Security CI + real Neon/PostgreSQL validation
   ↓
PR -> dev
   ↓
exact-commit Security CI
   ↓
immutable GHCR image -> Railway DEV
   ↓
live Clerk E2E when required Clerk IDs/secrets are configured
```

Increment G remains paused until the v1.4.2 corrected identity/authorization foundation is green.
