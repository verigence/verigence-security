# Phase 5 — Security Administration Foundation

**Status:** PARTIAL — Increments 1–2 validated on Neon DEV  
**Approved baseline:** Security Solution v1.3  
**Latest Neon validation run:** `31679363993`

## Objective

Build Security administration from the approved persistence model without inventing public API shapes or endpoint-level `security.*` permission keys that are not frozen by the approved design.

## Increment 1 — Tenant Security Policy and Retention Policy administration

Implemented internal administration for:

- `security.tenant_security_policies`;
- `security.security_retention_policies`.

The increment adds:

- `SecurityAdminRepository` for deterministic Tenant/configuration reads and transactional upserts;
- `TenantConfigurationService` for internal administration transactions;
- explicit configuration data classes with no hidden policy defaults;
- DRAFT/ACTIVE persistence exactly as permitted by the approved schema;
- compatibility proof that an ACTIVE policy written through Phase 5 is consumed unchanged by the existing runtime `SecurityRepository.get_tenant_policy()` path.

### Explicit Security configuration

Every approved threshold/TTL is supplied by configuration. No numeric Security default is introduced.

Retention values are also explicit, aligned with SEC-037: an ACTIVE Security retention policy is required before Tenant activation and retention day counts are Tenant configuration.

Initial Neon run `31678680842`: **SUCCESS**.

## Increment 2 — Tenant location and schedule administration

Implemented internal administration for:

- `security.tenant_locations`;
- `security.access_schedules`;
- `security.access_schedule_windows`.

The increment adds:

- `LocationAdminRepository` for Tenant-scoped location persistence;
- `ScheduleAdminRepository` for Tenant-scoped schedules and schedule windows;
- `TenantAccessConfigurationService` for transactional configuration;
- exact storage of location geo/radius/timezone/address/status values;
- exact storage of schedule status and normal/overnight window definitions;
- runtime compatibility proof using the existing `SecurityRepository.ensure_active_schedule()` and `SecurityRepository.schedule_windows()` path.

The implementation does not invent schedule replacement/deletion semantics. It creates or updates the explicitly supplied schedule/window identifiers only.

## Neon validation

Workflow: `.github/workflows/phase5-neon-admin.yml`  
Latest run: `31679363993`  
Result: **SUCCESS — 6/6 Phase 5 PostgreSQL tests passed**.

Validated behavior across Increments 1–2:

1. Security Policy DRAFT persistence preserves explicit configured values.
2. The same Tenant policy can be replaced with ACTIVE configuration without a duplicate row.
3. Existing runtime policy evaluation receives the exact ACTIVE administration values.
4. ACTIVE retention policy persistence preserves exact configured retention periods.
5. PostgreSQL CHECK constraints reject invalid retention configuration without partial writes.
6. Tenant location upsert preserves Tenant scope and exact geo/radius/timezone/address configuration.
7. Reconfiguring the same location identifier updates the row rather than creating a duplicate.
8. ACTIVE schedules and both normal/overnight windows written by administration are consumed by the existing runtime schedule repository.
9. Invalid location radius is rejected by the approved PostgreSQL constraint without a partial location row.

## Deliberately not implemented yet

- public administration routes;
- endpoint-level administrator permission checks;
- Tenant activation-readiness decision list;
- Tenant activation mutation;
- user/membership administration;
- employee-location assignment administration;
- role/permission/user-role administration;
- schedule-window removal/replacement semantics beyond explicit identifier upsert.

The exact public admin permission catalogue remains blocked. Phase 5 therefore continues through deterministic internal persistence/services first.

## Next safe increment

Continue with Tenant membership, employee-location assignment and RBAC administration persistence, then implement only activation-readiness prerequisites that are explicitly frozen by approved design.
