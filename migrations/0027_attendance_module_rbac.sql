-- Verigence Security v2 — Attendance Phase 1 permissions and secondary HRADMIN role
-- Additive/idempotent. Existing operating/admin role cardinality and mutation semantics are unchanged.

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

-- Attendance extends operating roles without changing the core platform role-default
-- catalogue. New Tenant creation reads both catalogues and materializes them into the
-- canonical tenant_role_permissions table.
CREATE TABLE IF NOT EXISTS security.module_operating_role_permission_defaults (
    module_key              varchar(80) NOT NULL,
    role_key                varchar(120) NOT NULL REFERENCES security.role_definitions(role_key),
    permission_key          varchar(180) NOT NULL REFERENCES security.permissions(permission_key),
    source_catalog_version  varchar(40),
    status                  varchar(20) NOT NULL CHECK (status IN ('ACTIVE','INACTIVE')),
    created_at_utc          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (module_key,role_key,permission_key)
);

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
)
INSERT INTO security.module_operating_role_permission_defaults
(module_key,role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT 'attendance',role_key,permission_key,'attendance-phase1','ACTIVE',CURRENT_TIMESTAMP
FROM operating_defaults
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE
SET source_catalog_version='attendance-phase1',status='ACTIVE';

-- Materialize Attendance grants for existing Tenants. This applies only to normal
-- tenant-scoped operating roles, never to the secondary HRADMIN role.
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
  JOIN security.module_operating_role_permission_defaults d
    ON d.module_key='attendance' AND d.status='ACTIVE'
  JOIN security.permissions p
    ON p.permission_key=d.permission_key AND p.status='ACTIVE'
  WHERE t.status IN ('CONFIGURING','ACTIVE')
  ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;
END $$;

-- HRADMIN is a secondary module role scoped to one Tenant. It is intentionally
-- outside role_definitions/user_tenant_operating_roles/user_admin_role_assignments,
-- so assigning HRADMIN never changes the employee's PC/TL/PM/CRM/Executive role.
CREATE TABLE IF NOT EXISTS security.module_roles (
    module_key      varchar(80) NOT NULL,
    role_key        varchar(80) NOT NULL,
    display_name    varchar(160) NOT NULL,
    status          varchar(20) NOT NULL CHECK (status IN ('ACTIVE','INACTIVE')),
    created_at_utc  timestamptz NOT NULL,
    updated_at_utc  timestamptz NOT NULL,
    PRIMARY KEY (module_key,role_key)
);

CREATE TABLE IF NOT EXISTS security.module_role_permissions (
    module_key      varchar(80) NOT NULL,
    role_key        varchar(80) NOT NULL,
    permission_key  varchar(180) NOT NULL REFERENCES security.permissions(permission_key),
    status          varchar(20) NOT NULL CHECK (status IN ('ACTIVE','INACTIVE')),
    created_at_utc  timestamptz NOT NULL,
    PRIMARY KEY (module_key,role_key,permission_key),
    FOREIGN KEY (module_key,role_key)
      REFERENCES security.module_roles(module_key,role_key)
);

CREATE TABLE IF NOT EXISTS security.user_module_role_assignments (
    assignment_id       uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES security.tenants(tenant_id) ON DELETE CASCADE,
    user_id             uuid NOT NULL REFERENCES security.users(user_id),
    module_key          varchar(80) NOT NULL,
    role_key            varchar(80) NOT NULL,
    status              varchar(20) NOT NULL CHECK (status IN ('ACTIVE','ENDED')),
    valid_from_utc      timestamptz,
    valid_to_utc        timestamptz,
    assigned_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
    assigned_at_utc     timestamptz NOT NULL,
    ended_at_utc        timestamptz,
    updated_at_utc      timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (module_key,role_key)
      REFERENCES security.module_roles(module_key,role_key),
    CHECK (valid_to_utc IS NULL OR valid_from_utc IS NULL OR valid_to_utc>valid_from_utc)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_user_module_role
ON security.user_module_role_assignments(tenant_id,user_id,module_key,role_key)
WHERE status='ACTIVE';

CREATE INDEX IF NOT EXISTS ix_user_module_roles_runtime
ON security.user_module_role_assignments(user_id,tenant_id,module_key,status);

INSERT INTO security.module_roles
(module_key,role_key,display_name,status,created_at_utc,updated_at_utc)
VALUES
('attendance','HRADMIN','HR Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (module_key,role_key) DO UPDATE
SET display_name=EXCLUDED.display_name,
    status='ACTIVE',
    updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
SELECT 'attendance','HRADMIN',permission_key,'ACTIVE',CURRENT_TIMESTAMP
FROM security.permissions
WHERE module_key='attendance' AND status='ACTIVE'
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE
SET status='ACTIVE';

COMMIT;
