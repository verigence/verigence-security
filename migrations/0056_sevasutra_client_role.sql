-- Verigence Security — SevaSutra client access (CLIENT operating role) and Super Admin oversight
--
-- Product owner, 9 Nov 2026 (docs/SEVASUTRA_MODULE_RBAC_2026-11-06.md, "Client access"):
--   * People who are not JBR employees -- a dealer principal, a service manager, an OEM or other
--     client person -- may be given SevaSutra's analytics, and nothing else. They hold the new
--     operating role CLIENT in the Project (one role per person per Project, as for every operating
--     role). What CLIENT shows is set once per Project: the Project's CLIENT bundle.
--   * The default CLIENT bundle is the analytics: sevasutra.project.read and sevasutra.analytics.read.
--     CLIENT holds no audit.* or di.* permission, so a sales-audit Project gives it nothing.
--   * Internal roles (ANALYST, TL, PM) are not restricted to employees.
--   * Super Admin oversees SevaSutra but does not sign off: approving an observation and settling
--     leakage stay with the Team Lead and the PM (services/v2_authorization.py, as payroll approval
--     stays with the CEO). No data change is needed for that part.
--
-- Additive and idempotent, in the shape of 0046 and 0052.

BEGIN;

-- 1. CLIENT as an OPERATING role.
INSERT INTO security.role_definitions
(role_key,role_class,display_name,status,created_at_utc,updated_at_utc)
VALUES
  ('CLIENT','OPERATING','Client (analytics)','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO NOTHING;

-- 2. The CHECK listing assignable operating-role keys, replaced under its existing name.
ALTER TABLE security.user_tenant_operating_roles
  DROP CONSTRAINT IF EXISTS user_tenant_operating_roles_role_key_check;

ALTER TABLE security.user_tenant_operating_roles
  ADD CONSTRAINT user_tenant_operating_roles_role_key_check
  CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER','ANALYST','CLIENT'));

-- 3. The platform default bundle: the analytics only.
WITH role_bundle(role_key,permission_keys) AS (
  VALUES
  ('CLIENT',ARRAY[
    'sevasutra.project.read',
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

-- 4. Projects provisioned before this migration hold their own copy of the bundles: CLIENT is
--    backfilled for each of them, the assigning actor carried from the tenant's existing rows.
--    New Projects receive it through provisioning, which seeds every OPERATING role's defaults.
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
  AND d.role_key='CLIENT'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
