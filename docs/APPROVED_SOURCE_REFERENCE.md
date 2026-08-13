# Approved Security Source Reference

Security implementation remains grounded in the approved Security v1.3 artifacts. The v1.3 OpenAPI is
referenced by its verified digest rather than silently regenerated or altered during code check-in.

The Security Admin Control Plane and its explicit v1.4 extensions are new, versioned design authorities. They do
not replace or rewrite v1.3 lifecycle contracts.

## Security v1.3 source artifacts

| Approved artifact | SHA-256 | Repository handling |
|---|---|---|
| `SECURITY_OPENAPI_v1.3.yaml` | `07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37` | Reviewed against implementation; authoritative copy remains in the approved Security v1.3 solution source |
| `SECURITY_POSTGRESQL_SCHEMA_v1.3.sql` | `175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d` | Committed byte-identically as `migrations/0001_security_baseline_v1.3.sql` |
| `SECURITY_DECISION_REGISTER_v1.3.md` | `a05b5e0f04cc63e5d76f54a3a120161aa8ce2172e7c810534c36445e85608070` | Committed byte-identically |
| `SECURITY_CORRELATION_STANDARD_v1.3.md` | `fa0f0886eaf6482e52c00ea612550d0674e5ed7b099bc6e9e2e71a84c1a1e1e0` | Committed byte-identically |
| `SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md` | `0c7c83ae08d4488951ff90e8c95c34eff7220b55da17329dc65699f91288cceb` | Committed byte-identically |

Any future copy of the approved v1.3 OpenAPI added to this repository must match the digest above or be
accompanied by an explicitly approved Security design-version change.

## Security Admin Control Plane v1.4

The repository-native versioned design authority for the new Admin Control Plane is:

```text
docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md
```

It governs only the new v1.4 administration/control-plane scope, including:

- Platform Super Admin bootstrap and Platform Admin authentication;
- direct Platform Admin Tenant creation;
- standard Platform/Tenant administrator roles;
- exact `security.*` administrator permission catalogue;
- Tenant groups;
- cross-module permission catalogue and module role templates;
- Tenant role/group/user authorization rules;
- RBAC authorization-version mutation rules;
- team-member invitation and human acceptance;
- privileged-access maker-checker;
- Admin API surface;
- v1.4 database extension plan;
- DI authorization-alignment plan;
- deployed Security-to-DI E2E acceptance criteria.

## Security Control Registry v1.4

The implementation authority for configurable Security enforcement switches is:

```text
docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md
```

It governs:

- Platform/Tenant effective Security-control resolution;
- configurable device/geo/schedule/network/refresh/admin checks;
- non-disableable core Security invariants;
- control hierarchy and override precedence;
- normalized control-registry persistence;
- Platform control-management APIs and audit requirements.

## Security Self-Onboarding v1.4

The implementation authority for token-gated self-onboarding is:

```text
docs/SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md
```

It governs:

- Tenant-scoped onboarding secret configuration by Platform Super Admin;
- Argon2id-only token persistence;
- `admin.self_onboarding` enable/disable control;
- authenticated USER self-registration using the Tenant token;
- PENDING-only membership/request creation;
- mandatory Tenant Admin approval before membership becomes ACTIVE;
- coexistence with invitation-led onboarding;
- privileged-role maker-checker retention;
- token rotation, duplicate handling, audit and deployed E2E acceptance criteria.

Where v1.4 explicitly resolves a former implementation ambiguity, implementation follows the applicable v1.4
design authority for that new scope.

Where v1.4 explicitly defers an issue, the issue remains blocked and must not be inferred.

The unavailable v1.3 OpenAPI continues to govern the older v1.3 lifecycle routes and is not superseded by these
v1.4 Admin extensions.
