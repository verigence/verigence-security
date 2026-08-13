# Security Admin Control Plane v1.4 — Increment A Validation

**Status:** VALIDATED ON NEON DEV — AWAITING PR PROMOTION  
**Date:** 2026-08-13  
**Feature branch:** `feature/phase5-admin-control-plane-schema`  
**Validated head:** `3d4f6e10d5efdbc01a475a2f440fb84bc86c68ca`  
**Neon validation run:** `31690567354`

## Scope validated

Increment A establishes the persistence/catalogue foundation defined by the approved v1.4 Admin Control Plane,
Security Control Registry and Self-Onboarding designs.

Implemented:

- additive migration `migrations/0002_security_admin_control_plane_v1.4.sql`;
- v1.4 extension of the existing canonical `security.permissions` catalogue;
- exact 44-key `security.*` Admin permission catalogue;
- four standard Platform roles and their exact permission bundles;
- drift-safe seeding for the eight reserved Tenant Admin roles;
- module and module-role-template persistence;
- Tenant Group, Group membership and Group-to-Role persistence;
- invitation persistence;
- privileged-access request persistence;
- structured Admin change/audit persistence;
- Security Control Registry definitions/settings/overrides;
- Tenant self-onboarding token settings using hash-only persistence;
- self-onboarding request persistence.

No v1.3 normative artifact or immutable baseline migration was modified.

## Real Neon evidence

Workflow `Phase 5 Neon Security Administration`, run `31690567354`, completed successfully.

The workflow first verified the immutable v1.3 baseline migration SHA-256:

```text
175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d
```

It then applied `0002_security_admin_control_plane_v1.4.sql` directly to Neon DEV with
`ON_ERROR_STOP=1` and a successful `COMMIT`.

Observed seed evidence from the migration run:

```text
Security Admin permissions:       44
Platform roles:                    4
Platform Super Admin permissions: 14
Platform Security Admin:           5
Module Catalog Admin:              4
Platform Auditor:                  6
Security Control definitions:     24
```

The accumulated Phase 5 PostgreSQL suite then completed:

```text
15/15 PASS
```

## Behaviors proven by Increment A tests

1. all nineteen new v1.4 control-plane tables exist in Neon DEV;
2. the seeded `security.*` Admin permission set exactly matches the v1.4 implementation authority;
3. all four Platform role bundles exactly match the approved bundles;
4. all twelve configurable Security controls and twelve non-disableable core controls exist with the approved
   configurability/default rules;
5. `admin.self_onboarding` defaults to disabled;
6. all eight reserved Tenant Admin roles can be seeded with their exact permission bundles;
7. repeated unchanged Tenant-role seeding is idempotent;
8. reserved Tenant Admin role drift is detected rather than silently overwritten;
9. Group relationships reject cross-Tenant Group membership through PostgreSQL constraints;
10. self-onboarding token persistence is hash-only with no plaintext token column;
11. duplicate open/effective self-onboarding requests for the same Tenant/user are rejected by PostgreSQL.

Temporary Tenant/USER/Group fixtures created by tests are cleaned after execution. The v1.4 schema and product
catalogue seeds remain deployed in Neon DEV.

## Correlation-ID compatibility

New v1.4 persistence uses `varchar(128)` for correlation IDs. This intentionally preserves the existing v1.3
correlation standard, which permits caller-supplied safe opaque values of 1–128 characters and does not require
UUID-only correlation IDs.

## Explicit non-claims

Increment A does **not** claim any of the following are implemented yet:

- Platform Super Admin bootstrap/login/password-change APIs;
- Platform Admin JWT issuance;
- direct Tenant creation/list/get/update APIs;
- runtime Security Control Registry evaluation;
- Security Control Registry Admin APIs;
- module catalogue HTTP APIs or DI synchronization;
- Group HTTP APIs or Group-derived runtime RBAC resolution;
- Tenant Role HTTP APIs;
- invitation acceptance APIs;
- self-onboarding submission/approval APIs;
- privileged maker-checker execution;
- deployed Admin Control Plane E2E.

Those remain later increments in the approved implementation sequence.

## Next increment after promotion

**Increment B — Platform Super Admin bootstrap, Platform Admin authentication and direct Tenant creation.**

Increment B must consume the persistence/catalogue foundation from this increment and must not hard-code or
commit the temporary bootstrap password.
