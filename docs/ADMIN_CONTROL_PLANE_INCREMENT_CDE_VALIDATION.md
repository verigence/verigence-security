# Admin Control Plane v1.4 — Increments C, D and E Validation

**Repository:** `verigence/verigence-security`  
**Date:** 2026-08-13  
**Status:** DONE / DEPLOYED

This document records implementation and promotion evidence for Admin Control Plane v1.4 Increments C, D and E. It does not replace the approved design in `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`.

## Increment C — Module Catalogue API + DI synchronization

**Status: DONE / DEPLOYED**

Implemented:

- Platform Module Catalogue list/detail/update APIs;
- `security.module.read` / `security.module.manage` enforcement;
- module namespace ownership validation;
- canonical permission validation;
- explicit `ACTIVE`, `DEPRECATED`, `RETIRED` lifecycle;
- omitted catalogue items are not implicitly deleted or deprecated;
- retirement is blocked when an effective Tenant role still depends on the permission;
- versioned module role templates restricted to their own module namespace;
- module-template updates do not silently mutate existing Tenant roles;
- structured Platform Admin audit evidence;
- initial DI synchronization grounded in current DI `dev`: 28 canonical `di.*` permissions and five approved USER-facing templates.

Evidence:

```text
Final feature head:              ada7fbe7a9fcb484dcafef78eba297bbc7025963
Final real-Neon validation:      31697061424 — PASS
PR:                              #43
PR Security CI:                  31699750982 — PASS
Promoted DEV commit:             5ae78f90759c565e359e407cd032a83d7c18fe57
Post-merge Security CI:          31699886106 — PASS
Railway DEV deployment/smoke:    31699886154 — PASS
```

Railway smoke passed exact-image deployment, `/health/ready`, `/health/live` and `X-Correlation-ID` verification.

## Increment D — Groups + effective RBAC

**Status: DONE / DEPLOYED**

Implemented:

- Tenant Group create/list/get/update APIs;
- Group member add/remove;
- Group role assign/remove;
- no nested Group model;
- Group inheritance affects roles/permissions only; location/schedule access remains explicit USER assignment;
- effective USER roles are the union of direct ACTIVE roles and ACTIVE Group-inherited roles;
- effective USER permissions are the union of ACTIVE permissions on effective roles;
- production USER access-session issuance uses Group-aware effective RBAC;
- effective RBAC changes increment `tenant_memberships.authorization_version` transactionally;
- Tenant-scoped Admin audit evidence is written for Group/RBAC mutations;
- Tenant Admin mutations resolve the authenticated Security USER and evaluate current effective permissions from PostgreSQL before mutation.

## Increment E — Tenant Role Admin APIs

**Status: DONE / DEPLOYED**

Implemented:

- Tenant Role list/create/get/update APIs;
- role permission add/remove;
- direct USER role assign/remove;
- permission discovery API;
- module role-template discovery API;
- role creation supports explicit permissions plus module `templateKeys`;
- template permissions are materialized into the Tenant role;
- applied catalogue-version provenance is stored in `role_template_bindings`;
- template changes never silently mutate existing Tenant roles;
- explicit template upgrade is additive and increments affected users' `authorization_version`;
- business roles cannot use reserved `platform.*` or standard `tenant.*` role keys.

Combined D/E promotion evidence:

```text
Final feature head:              e84101cd0a7e838a4c7f9f0cc9ce702dbabb3fb3
Final real-Neon validation:      31706796721 — PASS
PR:                              #44
PR Security CI:                  31706801264 — PASS
Promoted DEV commit:             f1fb7c9dab8a11773b85d9fbc09b7c14ec705ea4
Post-merge Security CI:          31706985353 — PASS
Railway DEV deployment/smoke:    31706985322 — PASS
```

Railway smoke passed exact-image deployment, `/health/ready`, `/health/live` and `X-Correlation-ID` verification.

## Runtime authorization result after D/E

```text
Authenticated USER
      ↓
ACTIVE Tenant membership
      ↓
Direct ACTIVE Tenant roles
      +
ACTIVE Group memberships → ACTIVE Group role assignments
      ↓
Effective Tenant roles
      ↓
ACTIVE registered permissions
      ↓
Security Access JWT roles[] + permissions[]
      ↓
DI/WPM authorize by permission key
```

Admin writes use current database RBAC rather than trusting stale role names. Business modules remain permission-driven.

## Next implementation pointer

**Increment F — Team-member onboarding:** invitation + acceptance and token-gated self-onboarding + Tenant Admin approval.

**Immediately after F — Clerk live integration:** bind live Clerk identities/invitations/onboarding to the now-stable USER/Tenant membership/RBAC/onboarding model and prove parity with deterministic DEV identity flows.

Then continue:

```text
Increment G  Privileged maker-checker
Increment H  Control Registry runtime/API + remaining policy/location/schedule/device Admin APIs
Increment I  DI authorization alignment
Increment J  Deployed Security → DI E2E
```
