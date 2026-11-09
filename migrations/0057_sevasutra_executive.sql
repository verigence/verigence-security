-- Verigence Security — SevaSutra access for the Executive operating role
--
-- Product owner, 9 Nov 2026: "lets have executive role in seva sutra.. it is required". Executive is the
-- senior oversight role in a Project (above the PM in Verigence's Task Manager). In SevaSutra the
-- Executive holds the PM's bundle: sees everything, approves, issues reports, settles leakage, governs
-- thresholds and the team. Capture stays with the Analyst on site, as for the PM.
--
-- Additive and idempotent, in the shape of 0052 and 0056.

BEGIN;

-- 1. The platform default bundle: the PM's SevaSutra permissions.
WITH role_bundle(role_key,permission_keys) AS (
  VALUES
  ('Executive',ARRAY[
    'sevasutra.project.read',
    'sevasutra.observation.approve',
    'sevasutra.report.issue',
    'sevasutra.leakage.verify',
    'sevasutra.leakage.settle',
    'sevasutra.risk.close',
    'sevasutra.benchmark.approve',
    'sevasutra.task.assign',
    'sevasutra.task.schedule',
    'sevasutra.settings.manage',
    'sevasutra.team.manage',
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

-- 2. Projects provisioned before this migration hold their own copy of the bundles: the Executive's
--    SevaSutra permissions are backfilled for each of them, the assigning actor carried from the tenant's
--    existing rows. New Projects receive it through provisioning.
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
  AND d.role_key='Executive'
  AND d.permission_key LIKE 'sevasutra.%'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
