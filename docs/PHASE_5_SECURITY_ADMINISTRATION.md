# Phase 5 — Security Administration Foundation

**Status:** PARTIAL — Increment 1 validated on Neon DEV  
**Approved baseline:** Security Solution v1.3  
**Neon validation run:** `31678680842`

## Objective

Build Security administration from the approved persistence model without inventing public API shapes or endpoint-level `security.*` permission keys that are not frozen by the approved design.

## Increment 1 — Tenant Security Policy and Retention Policy administration

Implemented internal administration for the two Tenant configuration records whose persistence contracts are explicit in the approved v1.3 schema:

- `security.tenant_security_policies`;
- `security.security_retention_policies`.

The increment adds:

- `SecurityAdminRepository` for deterministic Tenant/configuration reads and transactional upserts;
- `TenantConfigurationService` for internal administration transactions;
- explicit configuration data classes with no hidden policy defaults;
- DRAFT/ACTIVE persistence exactly as permitted by the approved schema;
- compatibility proof that an ACTIVE policy written through Phase 5 is consumed unchanged by the existing runtime `SecurityRepository.get_tenant_policy()` path.

### Security Policy configuration remains explicit

The administration service requires every approved threshold/value to be supplied:

- `max_active_devices_per_user`;
- `max_geo_accuracy_meters`;
- `max_geo_age_seconds`;
- `geo_revalidation_interval_seconds`;
- `access_token_ttl_minutes`;
- `machine_token_ttl_minutes`;
- `session_idle_timeout_minutes`;
- `session_max_duration_minutes`;
- `vpn_detected_action`;
- `vpn_unknown_action`;
- `configuration_version`;
- policy status.

No numeric Security default is introduced.

### Retention Policy configuration remains explicit

The service requires explicit values for:

- `access_context_retention_days`;
- `access_session_retention_days`;
- `security_event_retention_days`;
- policy status.

This is aligned with SEC-037: an ACTIVE Security retention policy is required before Tenant activation, and retention day counts are Tenant configuration rather than hidden defaults.

## Neon validation

Workflow: `.github/workflows/phase5-neon-admin.yml`  
Run: `31678680842`  
Result: **SUCCESS**.

Validated behavior:

1. Security Policy DRAFT persistence preserves explicit configured values.
2. The same Tenant policy can be replaced with ACTIVE configuration without creating a duplicate Tenant policy row.
3. The existing runtime policy reader receives the exact ACTIVE values written by the administration service.
4. ACTIVE retention policy persistence preserves exact configured retention periods.
5. Approved PostgreSQL CHECK constraints reject invalid administration values and the failed transaction does not leave a partial policy row.

## Deliberately not implemented in Increment 1

- public administration routes;
- endpoint-level administrator permission checks;
- Tenant activation-readiness decision list;
- Tenant activation mutation;
- user/membership administration;
- Tenant location administration;
- schedule/window administration;
- employee-location assignment administration;
- role/permission/user-role administration.

The exact public admin permission catalogue remains blocked. This increment therefore establishes the internal transaction/persistence foundation only.

## Next safe increment

Continue with deterministic administration persistence for Tenant memberships, locations, schedules and assignment relationships, followed by the subset of activation-readiness prerequisites that are explicitly frozen by approved design.
