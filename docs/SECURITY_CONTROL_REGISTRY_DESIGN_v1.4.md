# Verigence Security Control Registry Design v1.4

**Status:** APPROVED FOR IMPLEMENTATION  
**Date:** 2026-08-13  
**Extends:** `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`  
**Supersedes:** no Security v1.3 normative artifact.

## 1. Purpose

Security enforcement must be configurable without code deployment. A Platform Super Admin therefore manages a persisted **Security Control Registry** that determines whether configurable checks are enforcing globally and, where supported, for an individual Tenant.

A disabled check becomes non-enforcing; its configuration and historical evidence are retained.

## 2. Rules

1. No configurable check is enabled/disabled through code flags alone.
2. Every control has an explicit persisted default; no hidden application defaults are allowed.
3. Existing validated checks are seeded enabled so introduction of the registry does not silently weaken Security.
4. Core identity, Tenant isolation, RBAC, token validation, token expiry, audit, secret hashing and human onboarding acceptance are non-disableable.
5. Platform Super Admin owns control mutation in the first release.
6. Configurable controls have a Platform setting and may support a Tenant override: `INHERIT | ENABLED | DISABLED`.
7. Effective state is deterministic: non-configurable -> enabled; explicit Tenant override -> override; otherwise Platform setting.
8. Parent controls short-circuit child controls without rewriting child configuration.
9. Boolean switches determine **whether** a check enforces. Existing Tenant policy values determine **how** an enabled check evaluates.
10. Every control change requires a reason and a structured Admin audit record.

## 3. Initial configurable controls

| Control key | Default | Parent | Meaning when disabled |
|---|---:|---|---|
| `user_access.device_enforcement` | ON | — | device status/approval does not deny access; device context remains recorded |
| `user_access.device_limit` | ON | `user_access.device_enforcement` | active-device limit is not enforced |
| `user_access.geo_enforcement` | ON | — | geo-policy results do not deny access; location context may still be resolved |
| `user_access.geo_freshness` | ON | `user_access.geo_enforcement` | stale geo alone cannot deny |
| `user_access.geo_accuracy` | ON | `user_access.geo_enforcement` | accuracy threshold alone cannot deny |
| `user_access.geo_integrity` | ON | `user_access.geo_enforcement` | integrity/spoof signal alone cannot deny |
| `user_access.geo_radius` | ON | `user_access.geo_enforcement` | radius mismatch alone cannot deny |
| `user_access.schedule_enforcement` | ON | — | schedule mismatch cannot deny |
| `user_access.network_risk_enforcement` | ON | — | network/VPN result cannot deny |
| `user_access.refresh_geo_revalidation` | ON | `user_access.geo_enforcement` | refresh does not require fresh geo for enforcement |
| `admin.privileged_access_approval` | ON | — | maker-checker stage is bypassed; ordinary authorization/audit still apply |
| `admin.self_onboarding` | OFF | — | public self-onboarding endpoint is disabled even if a Tenant token exists |

## 4. Non-disableable controls

The registry exposes these for visibility but they are `configurable=false` and always effective:

- `core.identity_verification`
- `core.token_signature_validation`
- `core.token_issuer_audience_validation`
- `core.actor_type_validation`
- `core.principal_status_validation`
- `core.tenant_isolation`
- `core.tenant_membership_validation`
- `core.rbac_permission_enforcement`
- `core.token_expiry`
- `core.admin_audit`
- `core.onboarding_human_acceptance`
- `core.secret_hashing`

There is intentionally no switch that makes an authenticated user automatically authorized.

## 5. Runtime semantics

### Device enforcement OFF

Unknown/PENDING/BLOCKED/REVOKED device state does not deny solely through the device gate. Existing device records are not rewritten. Re-enabling the control immediately restores evaluation against persisted state.

### Geo enforcement OFF

Freshness/accuracy/integrity/radius cannot deny. The existing Security session/JWT location contract is not removed by this switch; a future locationless USER contract would require an explicit versioned design change.

### Schedule enforcement OFF

Schedule records remain stored; mismatch may be recorded but cannot deny.

### Network-risk enforcement OFF

Network risk may still be observed/audited, but its result cannot deny through this gate.

### Refresh geo revalidation OFF

Refresh does not fail merely because a new geo sample is missing or fails geo checks. Token expiry and original session maximum duration remain mandatory.

### RBAC remains mandatory

Even with all configurable contextual controls disabled, access still requires valid identity, active principal, correct Tenant, active Tenant membership, required permission and a valid bounded Security token/session.

## 6. Database model

Use a normalized registry rather than a wide Boolean table so new controls do not require a schema column for every switch.

### `security.security_control_definitions`

```text
control_key                  varchar PK
control_name                 varchar
category                     USER_ACCESS | ADMIN | CORE
parent_control_key           nullable FK -> security_control_definitions
configurable                 boolean
tenant_override_supported    boolean
default_enabled              boolean
description                  text
introduced_version           varchar
status                       ACTIVE | RETIRED
sort_order                   integer
```

### `security.platform_security_control_settings`

```text
control_key                  PK/FK
enabled                      boolean
configuration_version        bigint >= 1
updated_by_user_id           FK -> security.users
updated_at_utc               timestamptz
change_reason                text NOT NULL
```

### `security.tenant_security_control_overrides`

```text
tenant_id                    FK -> security.tenants
control_key                  FK -> security_control_definitions
override_mode                INHERIT | ENABLED | DISABLED
configuration_version        bigint >= 1
updated_by_user_id           FK -> security.users
updated_at_utc               timestamptz
change_reason                text NOT NULL
PRIMARY KEY (tenant_id, control_key)
```

Definitions are product-controlled seed data. Admin APIs cannot invent arbitrary control keys.

## 7. Admin APIs

Platform control endpoints:

```text
GET   /security/v1/platform/security-controls
PATCH /security/v1/platform/security-controls/{controlKey}
GET   /security/v1/platform/tenants/{tenantId}/security-controls
PUT   /security/v1/platform/tenants/{tenantId}/security-controls/{controlKey}
```

Mutation requires Platform Super Admin in the first release and a non-empty `changeReason`.

## 8. Evaluation contract

Security resolves the effective control set once per access/session decision and passes that immutable effective-control snapshot through the evaluation pipeline. Individual policy components do not independently query the database for switches.

This prevents one request from observing inconsistent control values halfway through evaluation.

The effective control state used for a decision is included in access evidence by control/version reference rather than by silently changing historical policy records.

## 9. Implementation acceptance

Implementation is complete only when real Neon and deployed DEV tests prove:

- defaults preserve current behavior;
- Platform ON/OFF affects enforcement without deleting policy state;
- Tenant override precedence is deterministic;
- parent control short-circuit works;
- non-configurable controls reject mutation;
- changes are audited with actor/reason/correlation;
- RBAC/Tenant isolation still deny while contextual controls are disabled;
- re-enabling a control restores evaluation against existing persisted records.
