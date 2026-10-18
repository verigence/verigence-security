-- Verigence Security — REVIEWER operating role
--
-- A Reviewer sits at one physical location, is mapped to several Dealer
-- Outlets, and reviews what a Process Consultant captured across all of them:
-- opens every uploaded document, corrects values Document Intelligence read
-- wrongly, and marks a journey's Booking or Delivery documents reviewed.
--
-- The bundle is AUDIT_CORE_DEFAULT_ROLE_BUNDLES_v1.1 section 8. It differs
-- from CRM by exactly one permission, audit.journey.update: a Reviewer
-- corrects a value where CRM reads only. It withholds audit.evidence.upload so
-- a Reviewer cannot upload, and the whole audit.work.* family so a Reviewer
-- cannot close a task -- limits carried by the token rather than by a
-- role-name check inside Audit Core.
--
-- Additive and idempotent, in the shape of 0013: permissions are referenced,
-- never created here, and every insert tolerates a re-run.

BEGIN;

-- 1. The role itself. user_tenant_operating_roles.role_key and
--    platform_role_permission_defaults.role_key both reference this table, so
--    nothing below can be inserted until the definition exists.
INSERT INTO security.role_definitions
(role_key,role_class,display_name,status,created_at_utc,updated_at_utc)
VALUES
  ('REVIEWER','OPERATING','Reviewer','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO NOTHING;

-- 2. An operating-role assignment is also gated by a CHECK listing the allowed
--    keys, which would reject REVIEWER however the role is seeded. The
--    constraint is replaced rather than widened in place, under its existing
--    name, so the table keeps one obvious constraint to read.
ALTER TABLE security.user_tenant_operating_roles
  DROP CONSTRAINT IF EXISTS user_tenant_operating_roles_role_key_check;

ALTER TABLE security.user_tenant_operating_roles
  ADD CONSTRAINT user_tenant_operating_roles_role_key_check
  CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER'));

-- 3. Fail loudly rather than seed a partial bundle: every permission the
--    Reviewer needs must already be registered and ACTIVE from 0013.
DO $$
DECLARE missing_count integer;
BEGIN
  WITH required(permission_key) AS (
    SELECT unnest(ARRAY[
      'audit.project.read',
      'audit.master.read',
      'audit.customer.read',
      'audit.journey.read',
      'audit.journey.update',
      'audit.evidence.read',
      'audit.evidence.refresh',
      'audit.finding.read',
      'audit.analytics.read',
      'di.subject.read',
      'di.document.read',
      'di.document.content.read',
      'di.document.fields.read',
      'di.document.quality.read'
    ]::varchar[])
  )
  SELECT count(*) INTO missing_count
  FROM required r
  LEFT JOIN security.permissions p ON p.permission_key=r.permission_key
  WHERE p.permission_key IS NULL OR p.status <> 'ACTIVE';

  IF missing_count <> 0 THEN
    RAISE EXCEPTION
      'REVIEWER operating-role defaults reference % missing/non-ACTIVE permission(s)',
      missing_count;
  END IF;
END $$;

-- 4. The platform default bundle.
WITH role_bundle(role_key,permission_keys) AS (
  VALUES
  ('REVIEWER',ARRAY[
    -- Read the deal the Reviewer is checking.
    'audit.project.read',
    'audit.master.read',
    'audit.customer.read',
    'audit.journey.read',
    -- Correct a value Document Intelligence read wrongly. This one permission
    -- is the whole capability difference from CRM.
    'audit.journey.update',
    -- Open each uploaded document, and ask DI for its values again.
    'audit.evidence.read',
    'audit.evidence.refresh',
    -- See the findings on the deal, without raising or adjudicating any.
    'audit.finding.read',
    -- Their own daily and weekly review counts.
    'audit.analytics.read',
    -- Read the document itself and the fields extracted from it. No upload,
    -- and no verification write.
    'di.subject.read',
    'di.document.read',
    'di.document.content.read',
    'di.document.fields.read',
    'di.document.quality.read'
  ]::varchar[])
),
approved_defaults AS (
  SELECT role_key,unnest(permission_keys) AS permission_key
  FROM role_bundle
)
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT role_key,permission_key,
       CASE WHEN permission_key LIKE 'audit.%' THEN 'audit-2.1'
            ELSE 'di-phase1-approved' END,
       'ACTIVE',CURRENT_TIMESTAMP
FROM approved_defaults
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- 5. Tenants provisioned before this migration already hold their own copy of
--    the operating-role bundles in tenant_role_permissions, and nothing
--    re-seeds an existing tenant. Without this backfill a Reviewer would work
--    only in tenants created afterwards, and resolve no permissions at all in
--    the ones already running.
--
--    The assigning actor is carried from that tenant's existing rows, so the
--    backfill is attributed to whoever provisioned the tenant rather than to a
--    synthetic identity.
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
  AND d.role_key='REVIEWER'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
