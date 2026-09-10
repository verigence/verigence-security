-- Keep the temporary PC Analytics expansion tenant-scoped rather than changing
-- the frozen platform operating-role default catalog. Existing tenant grants
-- created by 0030 remain ACTIVE, so PC retains Analytics access for all current
-- Analytics-enabled tenants. This is easier to narrow later without changing
-- the permanent platform role baseline.

BEGIN;

DELETE FROM security.platform_role_permission_defaults
WHERE role_key = 'PC'
  AND permission_key = 'audit.analytics.read'
  AND source_catalog_version = 'audit-analytics-open-access';

COMMIT;
