# Verigence Security — Default Platform Role Templates

**Document ID:** VSEC-SD-RBAC-001  
**Version:** 1.0  
**Status:** APPROVED ARCHITECTURE INPUT  
**Date:** 2026-08-15  
**Owner decision:** Seed four default operational roles for onboarding; Super Admin and Tenant Admin may customize them within defined authority

## 1. Purpose

Security owns the canonical effective permission set placed in Verigence access tokens. To simplify Tenant onboarding, Security SHALL provide four operational role templates by default:

- `PC` — Process Consultant
- `TL` — Team Lead
- `PM` — Project Manager / PMO operating role
- `CRM` — CRM operator

Each template is a cross-module bundle containing approved Audit Core (`audit.*`) and Document Intelligence (`di.*`) permissions. `permissions[]` remains authoritative at runtime; modules never authorize by role-name string.

`SUPER_ADMIN` and `TENANT_ADMIN` are Security administration roles. They are not part of the four operational defaults. Audit Core `Executive` remains a separate special role and is not one of these onboarding templates.

## 2. Onboarding and override semantics

Security SHALL maintain a versioned platform-default definition of the four operational templates.

Tenant onboarding clones/seeds the current platform defaults into Tenant-owned role-template records. After that:

- Tenant Admin may edit PC/TL/PM/CRM for its own Tenant;
- Super Admin may edit those roles for any Tenant;
- Super Admin may edit the platform defaults used for future Tenant onboarding;
- changing platform defaults does not silently rewrite an existing Tenant's seeded/customized roles;
- an explicit reset/reseed operation is required to replace Tenant role definitions with a later platform default;
- role changes take effect on newly issued/refreshed tokens; existing short-lived tokens remain valid until expiry/revocation according to normal token policy.

## 3. Administration permissions

Security registers these administration permissions:

- `security.role_template.read`
- `security.role_template.tenant.write`
- `security.role_template.platform.write`

Default administration bundles:

- `TENANT_ADMIN`: `security.role_template.read`, `security.role_template.tenant.write`
- `SUPER_ADMIN`: all three permissions

Tenant Admin authorization additionally requires the token `tenant_id` to equal the Tenant being changed. Super Admin may operate across Tenants.

## 4. Editable-template safety rules

PC/TL/PM/CRM may be customized only with permissions registered in the Security platform permission catalogue.

For these four operational roles:

- `security.*` permissions are forbidden;
- `di.platform.whatsapp.admin` is forbidden;
- `di.document.delete` is forbidden;
- unknown/unregistered permissions are rejected;
- empty role templates are allowed only through an explicit admin update and remain auditable;
- every change records actor, Tenant/scope, role key, previous permissions, new permissions, time and request/correlation identifier where available.

These hard guards prevent an operational role editor from turning PC/TL/PM/CRM into Security or platform-administration identities.

## 5. Default operational bundles

The machine-readable source is `config/default_role_templates.json`. The human-readable mapping is identical to the approved Audit Core amendment `VAC-SD-RBAC-001`.

### PC

Audit Core: project/master read; customer capture; Journey create/read/update/submit; evidence read/upload/refresh; payment/delivery/trade-in read+write; finding read/create; work read/update; Daily/EOD read+execute.

DI: subject create/read; document upload/read/content/fields/quality read; entity-link read/write.

**No formal verification-write permission.**

### TL

Audit Core: project/master/customer/Journey read; evidence read/refresh; payment/delivery/trade-in read+verify; finding read/create/update; review read/decide; work read/update/manage; Daily/EOD read/review; escalation read; analytics read.

DI: subject/document/content/fields/quality read; verification read/write; operations read.

### PM

Audit Core: project read/update/assignment management; master/customer/Journey read; evidence read/refresh; payment/delivery/trade-in read+verify; finding read/create/update/resolve; review read/decide; work read/update/manage; Daily/EOD read/review; CRM read/manage; escalation read/manage; analytics and audit-trail read.

DI: subject/document/content/fields/quality read; verification read/write; operations read.

PM permission does not override Audit Core's configured business policy for when PM verification/review is applicable.

### CRM

Audit Core: project/customer/Journey/evidence/finding read; work read/update; CRM read/execute; escalation read.

DI: subject/document/content/fields/quality read only.

## 6. Permission catalogues

Audit Core canonical permissions are registered from `design/AUDIT_CORE_SECURITY_CATALOG_v2.1.json` in `verigence-audit-core`.

DI canonical permissions are taken from the current DI implementation catalogue in `backend/src/verigence/di/auth/permissions.py`, including the canonical module-prefixed `di.*` names.

Security SHALL not translate these to a second competing permission vocabulary.

## 7. Effective token calculation

For a user with one or more roles:

```text
Tenant role-template permissions
UNION approved direct grants
= effective platform permissions[]
```

The resulting user token may contain both `audit.*` and `di.*` permissions. Audit Core consumes its own permissions. When Audit Core calls DI synchronously for a user action, Security token exchange narrows the downstream token to:

```text
user effective platform authority
INTERSECT Audit Core integration authority
INTERSECT requested DI operation authority
```

## 8. Persistence

Tenant role templates and platform defaults are Security-owned persistent configuration. They SHALL NOT exist only in process memory or deployment environment variables.

The implementation uses Security persistence so customized Tenant roles survive service restart/deployment and can be audited/versioned.

## 9. Implementation task

This design creates `SEC-RBAC-001` in `docs/SECURITY_IMPLEMENTATION_TASKS.md` for default role catalogue, Tenant seeding/override persistence, Super Admin/Tenant Admin management APIs, effective token resolution and tests.
