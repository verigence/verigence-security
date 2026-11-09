-- Verigence Security — SevaSutra access for the PC operating role
--
-- Product owner, 9 Nov 2026: "PC = Analyst in SevaSutra". The dealership's PC is SevaSutra's on-site
-- auditor: in a service-audit Project the PC holds the Analyst's bundle (capture, verify, raise
-- observations, propose benchmarks, analytics) at the outlets mapped to them. Whoever raises an
-- observation never approves it: the PC, like the Analyst, holds no approve permission.
--
-- Additive and idempotent, in the shape of 0052, 0056 and 0057.

BEGIN;

-- 1. The platform default bundle: the Analyst's SevaSutra permissions.
WITH role_bundle(role_key,permission_keys) AS (
  VALUES
  ('PC',ARRAY[
    'sevasutra.project.read',
    'sevasutra.evidence.upload',
    'sevasutra.evidence.verify',
    'sevasutra.observation.raise',
    'sevasutra.benchmark.propose',
    'sevasutra.analytics.read'
  ]::varchar[])
),
approved_defaults AS (
  SELECT role_key,unnest(permission_keys) AS permission_key
  FROM role_bundle
)
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT role_key,permission_key,'sevasutra-1.0','ACTIVE',CURRENT_TIMESTAMP
FROM approved_defaults
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- 2. Projects provisioned before this migration hold their own copy of the bundles: the PC's SevaSutra
--    permissions are backfilled for each of them. New Projects receive it through provisioning.
INSERT INTO security.tenant_role_permissions
(tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
SELECT existing.tenant_id,
       d.role_key,
       d.permission_key,
       existing.assigned_by_user_id,
       CURRENT_TIMESTAMP
FROM security.platform_role_permission_defaults d
JOIN security.permissions p
  ON p.permission_key=d.permission_key
 AND p.status='ACTIVE'
JOIN (
  SELECT DISTINCT ON (tenant_id) tenant_id,assigned_by_user_id
  FROM security.tenant_role_permissions
  ORDER BY tenant_id,assigned_at_utc
) AS existing ON true
WHERE d.status='ACTIVE'
  AND d.role_key='PC'
  AND d.permission_key LIKE 'sevasutra.%'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
