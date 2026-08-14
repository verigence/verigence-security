# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2  
**Last updated:** 2026-08-14

## 1. Governing recovery rule

Implementation is grounded in approved/versioned repository artifacts, not chat reconstruction.

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
3. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
4. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md` for unchanged Clerk rules;
5. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md` for unchanged Admin scope;
6. `docs/IMPLEMENTATION_STATUS.md`;
7. `docs/APPROVED_SOURCE_REFERENCE.md`;
8. `docs/SECURITY_DECISION_REGISTER_v1.3.md`;
9. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`;
10. applicable Phase 4/Phase 5 validation artifacts;
11. current Security `dev`, open Security PRs and CI/Railway state.

When documents conflict on human onboarding or Tenant membership, v1.4.2 is the controlling amendment.

## 2. Critical identity/authorization invariant

Do not reconstruct or restart the old Tenant-scoped human onboarding model.

```text
Human identity onboarding = Platform-global, once per person
Tenant access              = role/group/location/schedule authorization assignment
Clerk                      = authentication provider
Security                   = USER lifecycle + authorization authority
```

A person has one Security USER and one Clerk mapping. The same Security `user_id` may receive independent roles
in multiple Tenants without another onboarding process.

`security.tenant_memberships` is historical/migration debt after v1.4.2 and is not an active runtime USER-access
prerequisite.

## 3. Current promoted baseline before v1.4.2

```text
DEV commit: 0464adf353bf23cd7acf85db4368c3d456a06b34
```

This baseline includes Admin Control Plane increments A–F historically and the Clerk v1.4.1 Platform boundary.

Clerk cutover evidence:

```text
Security CI: 31728164273 — PASS
Railway DEV: 31728164126 — PASS
Railway deployment: 79f026f5-0bbf-4601-856b-a9a7f4e678c6
```

## 4. Current workstream

**NOW:** Global USER Onboarding v1.4.2.

Feature branch:

```text
feature/global-user-onboarding-v1.4.2
```

Required sequence:

```text
v1.4.2 design frozen
      ↓
additive migration 0003
      ↓
global onboarding key + USER PENDING lifecycle
      ↓
Security-first Clerk invitation/binding
      ↓
Security Admin activation + Clerk lifecycle sync
      ↓
remove Tenant onboarding/membership runtime gates
      ↓
per-user/per-Tenant authorization state
      ↓
real PostgreSQL acceptance tests
      ↓
Security CI + Neon
      ↓
PR -> dev
      ↓
Railway DEV exact-digest proof
```

Increment G maker-checker is **PAUSED** until this corrected foundation and required live Clerk identity proof are
green.

## 5. v1.4.2 rules that must survive every reset

### Global onboarding key

One Platform-level key only. It is retrievable/shareable by authorized Platform administrators, rotatable and
disable-able. It starts onboarding but grants no Tenant/application access.

### Ordering

Security validates the global onboarding key and commits a PENDING Security USER/onboarding request **before**
calling Clerk provisioning.

### Activation

Clerk account creation/authentication never activates Verigence access. Security Admin explicitly changes the
Security USER to ACTIVE.

### Deactivation

Security status is authoritative. Suspend/disable/exit revokes Security sessions and synchronizes a Clerk ban.
Allowed reactivation synchronizes Clerk unban before committing Security ACTIVE.

### Tenant authorization

No Tenant membership is required. Tenant access requires active global USER + active Tenant + effective
Tenant-scoped authorization + device/location/schedule/network/security controls.

### Authorization version

Use `security.user_tenant_authorization_state`, not Tenant membership, as the per-user/per-Tenant authorization
version carrier.

## 6. Active v1.4.2 API direction

```text
Platform onboarding key:
GET/PUT/DELETE /security/v1/platform/user-onboarding/key
POST           /security/v1/platform/user-onboarding/key/rotate

Global onboarding:
POST /security/v1/onboarding/users
POST /security/v1/onboarding/users/{requestId}/bind

Authentication precheck:
POST /security/v1/auth/precheck

Global USER administration:
GET   /security/v1/platform/users
PATCH /security/v1/platform/users/{userId}/status
```

Tenant-scoped identity invitation/self-onboarding endpoints from Increment F are retired from the active route
table by v1.4.2.

## 7. Live configuration dependencies

Do not put secrets in repository files.

Live global onboarding/lifecycle requires deployment configuration for:

```text
CLERK_SECRET_KEY
SECURITY_USER_ONBOARDING_KEY_ENCRYPTION_KEY
```

Clerk verifier configuration from v1.4.1 remains required.

The first Platform Super Admin live claim still requires the intended immutable Clerk `user_...` identifier.

## 8. Other blockers/deferred work

Still unresolved unless a later tracker says otherwise:

- complete SEC-032 Tenant activation prerequisite catalogue;
- persistent cross-replica idempotency store;
- device BLOCKED vs REVOKED business semantics;
- legacy v1.3 lifecycle route shapes dependent on unavailable v1.3 OpenAPI;
- exact recent-MFA freshness threshold for privileged operations;
- broader Clerk webhook lifecycle semantics;
- SYSTEM/SERVICE_INTEGRATION issuance;
- retention/offboarding execution;
- overlapping JWKS rotation;
- WPM catalogue;
- UAT/Production readiness.

## 9. Promotion discipline

```text
feature/*
   ↓ real Neon tests + Security CI
  dev
   ↓ exact-commit Security CI
immutable GHCR image
   ↓
Railway DEV
   ↓ readiness + liveness + correlation
```

Do not move to Increment G or Phase 6 because of context loss. Follow the current v1.4.2 tracker.
