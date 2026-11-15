-- Verigence Security — SevaSutra Uploader (UPLOADER operating role) and the papers.submit permission
--
-- Product owner, 15 Nov 2026: SevaSutra moves from keying papers in by hand to reading them. The
-- dealership's own people -- a Service Advisor first, a gate security guard for the gate register --
-- scan the papers on the SevaSutra app and upload them; SevaSutra reads them and runs its checks.
--   * They are not JBR employees. They hold the new operating role UPLOADER in the Project, mapped to
--     the outlets they work at (outlet-scoped, like the PC).
--   * UPLOADER may scan and upload papers, and nothing else: no evidence review, no observations, no
--     analytics. The default bundle is sevasutra.project.read and the new sevasutra.papers.submit.
--   * sevasutra.papers.submit is its own permission so that an Uploader gets the scanner without the
--     PC's evidence.upload (which also takes DMS files). The PC, Analyst and TL keep scanning through
--     evidence.upload; SevaSutra lets evidence.upload submit papers too.
--
-- Additive and idempotent, in the shape of 0052, 0056 and 0058.

BEGIN;

-- 1. The new permission, in the SevaSutra catalogue.
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
  ('sevasutra.papers.submit','sevasutra','papers','submit',NULL,'ACTIVE','sevasutra.papers.submit','sevasutra-1.0',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key='sevasutra',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='sevasutra-1.0',
    updated_at_utc=CURRENT_TIMESTAMP;

-- 2. UPLOADER as an OPERATING role.
INSERT INTO security.role_definitions
(role_key,role_class,display_name,status,created_at_utc,updated_at_utc)
VALUES
  ('UPLOADER','OPERATING','Uploader (scans papers)','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO NOTHING;

-- 3. The CHECK listing assignable operating-role keys, replaced under its existing name.
ALTER TABLE security.user_tenant_operating_roles
  DROP CONSTRAINT IF EXISTS user_tenant_operating_roles_role_key_check;

ALTER TABLE security.user_tenant_operating_roles
  ADD CONSTRAINT user_tenant_operating_roles_role_key_check
  CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER','ANALYST','CLIENT','UPLOADER'));

-- 4. The platform default bundle: scan and upload papers, nothing else.
WITH role_bundle(role_key,permission_keys) AS (
  VALUES
  ('UPLOADER',ARRAY[
    'sevasutra.project.read',
    'sevasutra.papers.submit'
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

-- 5. Projects provisioned before this migration hold their own copy of the bundles: UPLOADER is
--    backfilled for each of them. New Projects receive it through provisioning.
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
  AND d.role_key='UPLOADER'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
