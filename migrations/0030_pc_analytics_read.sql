-- Temporary Analytics access expansion: Process Coordinators receive the same
-- tenant Analytics dashboard read permission as TL/PM/Executive.
-- Future employee/role scoping can narrow Analytics data without changing this
-- service boundary. Additive and idempotent.

BEGIN;

-- Make PC part of the platform default so newly provisioned tenants inherit
-- Analytics read access as well.
INSERT INTO security.platform_role_permission_defaults
(role_key, permission_key, source_catalog_version, status, created_at_utc)
VALUES
('PC', 'audit.analytics.read', 'audit-analytics-open-access', 'ACTIVE', CURRENT_TIMESTAMP)
ON CONFLICT (role_key, permission_key)
DO UPDATE SET
  status = 'ACTIVE',
  source_catalog_version = EXCLUDED.source_catalog_version;

-- Backfill existing tenants that already have Analytics enabled for an
-- operating role. Reuse the existing assignment actor for that tenant.
WITH analytics_tenants AS (
  SELECT DISTINCT ON (tenant_id)
         tenant_id,
         assigned_by_user_id
  FROM security.tenant_role_permissions
  WHERE permission_key = 'audit.analytics.read'
  ORDER BY tenant_id, assigned_at_utc
)
INSERT INTO security.tenant_role_permissions
(tenant_id, role_key, permission_key, assigned_by_user_id, assigned_at_utc)
SELECT tenant_id,
       'PC',
       'audit.analytics.read',
       assigned_by_user_id,
       CURRENT_TIMESTAMP
FROM analytics_tenants
ON CONFLICT DO NOTHING;

COMMIT;
