-- Verigence Security v2 — Attendance Phase 1 permissions and secondary HRAdmin role
-- Reuses the existing Security role/permission/admin-assignment constructs.
-- No parallel Attendance RBAC tables are introduced.

BEGIN;

WITH attendance_permissions(permission_key,module_key,resource_key,action_key) AS (
  VALUES
    ('attendance.self.read','attendance','self','read'),
    ('attendance.self.checkin','attendance','self','checkin'),
    ('attendance.self.checkout','attendance','self','checkout'),
    ('attendance.team.read','attendance','team','read'),
    ('attendance.all.read','attendance','all','read'),
    ('attendance.location.read','attendance','location','read'),
    ('attendance.exception.read','attendance','exception','read'),
    ('attendance.exception.resolve','attendance','exception','resolve'),
    ('attendance.correction.write','attendance','correction','write'),
    ('attendance.policy.read','attendance','policy','read'),
    ('attendance.policy.manage','attendance','policy','manage'),
    ('attendance.report.read','attendance','report','read'),
    ('attendance.report.export','attendance','report','export')
)
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
SELECT permission_key,module_key,resource_key,action_key,NULL,'ACTIVE',permission_key,
       'attendance-phase1',CURRENT_TIMESTAMP
FROM attendance_permissions
ON CONFLICT (permission_key) DO UPDATE
SET module_key=EXCLUDED.module_key,
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='attendance-phase1',
    updated_at_utc=CURRENT_TIMESTAMP;

-- HRAdmin is an ADMIN role, but unlike TenantAdmin/ModuleAdmin/SuperAdmin it is secondary:
-- the same USER may continue to hold one normal operating role for Audit/DI.
INSERT INTO security.role_definitions
(role_key,role_class,display_name,status,created_at_utc,updated_at_utc)
VALUES ('HRAdmin','ADMIN','HR Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO UPDATE
SET role_class='ADMIN',display_name='HR Administrator',status='ACTIVE',updated_at_utc=CURRENT_TIMESTAMP;

-- The original v2 table intentionally allowed only the three primary admin roles.
-- Extend those existing CHECK constraints in place so HRAdmin uses the same assignment table.
DO $$
DECLARE item record;
BEGIN
  FOR item IN
    SELECT c.conname, pg_get_constraintdef(c.oid) AS definition
    FROM pg_constraint c
    JOIN pg_class t ON t.oid=c.conrelid
    JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='security'
      AND t.relname='user_admin_role_assignments'
      AND c.contype='c'
      AND pg_get_constraintdef(c.oid) ILIKE '%role_key%'
  LOOP
    EXECUTE format(
      'ALTER TABLE security.user_admin_role_assignments DROP CONSTRAINT %I',
      item.conname
    );
  END LOOP;
END $$;

ALTER TABLE security.user_admin_role_assignments
ADD CONSTRAINT ck_user_admin_role_assignments_role_key
CHECK (role_key IN ('SuperAdmin','TenantAdmin','ModuleAdmin','HRAdmin'));

ALTER TABLE security.user_admin_role_assignments
ADD CONSTRAINT ck_user_admin_role_assignments_scope
CHECK (
  (role_key='SuperAdmin' AND scope_type='PLATFORM' AND scope_id IS NULL)
  OR
  (role_key='TenantAdmin' AND scope_type='TENANT' AND scope_id IS NOT NULL)
  OR
  (role_key='ModuleAdmin' AND scope_type='MODULE' AND scope_id IS NOT NULL)
  OR
  (role_key='HRAdmin' AND scope_type='TENANT' AND scope_id IS NOT NULL)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_v2_active_hradmin_user_tenant_scope
ON security.user_admin_role_assignments(user_id,scope_id)
WHERE status='ACTIVE' AND role_key='HRAdmin';

-- Operating-role defaults are additive and preserve the existing primary role model.
WITH operating_defaults(role_key,permission_key) AS (
  VALUES
    ('PC','attendance.self.read'),
    ('PC','attendance.self.checkin'),
    ('PC','attendance.self.checkout'),
    ('TL','attendance.self.read'),
    ('TL','attendance.self.checkin'),
    ('TL','attendance.self.checkout'),
    ('TL','attendance.team.read'),
    ('PM','attendance.self.read'),
    ('PM','attendance.self.checkin'),
    ('PM','attendance.self.checkout'),
    ('PM','attendance.all.read'),
    ('PM','attendance.report.read'),
    ('CRM','attendance.self.read'),
    ('CRM','attendance.self.checkin'),
    ('CRM','attendance.self.checkout'),
    ('Executive','attendance.self.read'),
    ('Executive','attendance.self.checkin'),
    ('Executive','attendance.self.checkout'),
    ('Executive','attendance.all.read'),
    ('Executive','attendance.report.read')
),
hradmin_defaults(role_key,permission_key) AS (
  SELECT 'HRAdmin',permission_key
  FROM security.permissions
  WHERE module_key='attendance' AND status='ACTIVE'
),
all_defaults AS (
  SELECT * FROM operating_defaults
  UNION ALL
  SELECT * FROM hradmin_defaults
)
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT role_key,permission_key,'attendance-phase1','ACTIVE',CURRENT_TIMESTAMP
FROM all_defaults
ON CONFLICT (role_key,permission_key) DO UPDATE
SET source_catalog_version='attendance-phase1',status='ACTIVE';

-- Materialize the new defaults for existing active Tenants using the same grant-audit
-- convention as the v2 reconciliation migration.
DO $$
DECLARE super_admin_user uuid;
BEGIN
  SELECT user_id INTO super_admin_user
  FROM security.user_admin_role_assignments
  WHERE role_key='SuperAdmin' AND scope_type='PLATFORM' AND status='ACTIVE'
  LIMIT 1;
  IF super_admin_user IS NULL THEN
    RAISE EXCEPTION 'Attendance RBAC migration requires canonical active SuperAdmin';
  END IF;

  INSERT INTO security.tenant_role_permissions
  (tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
  SELECT t.tenant_id,d.role_key,d.permission_key,super_admin_user,CURRENT_TIMESTAMP
  FROM security.tenants t
  JOIN security.platform_role_permission_defaults d
    ON d.status='ACTIVE' AND d.source_catalog_version='attendance-phase1'
  WHERE t.status='ACTIVE'
  ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;
END $$;

COMMIT;
