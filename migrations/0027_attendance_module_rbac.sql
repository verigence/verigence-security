-- Verigence Security v2 — Attendance Phase 1 module permissions and secondary HRADMIN role
-- Additive/idempotent. The secondary module role is deliberately separate from operating/admin roles.

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

-- Operating-role defaults remain the normal role source. HRADMIN is a secondary module role.
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
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT role_key,permission_key,'attendance-phase1','ACTIVE',CURRENT_TIMESTAMP
FROM operating_defaults
ON CONFLICT (role_key,permission_key) DO UPDATE
SET source_catalog_version='attendance-phase1',status='ACTIVE';

-- Materialize the new defaults for existing Tenant roles without disturbing any existing grant.
INSERT INTO security.tenant_role_permissions (tenant_id,role_key,permission_key,created_at_utc)
SELECT tr.tenant_id,d.role_key,d.permission_key,CURRENT_TIMESTAMP
FROM security.tenant_roles tr
JOIN security.platform_role_permission_defaults d
  ON d.role_key=tr.role_key AND d.status='ACTIVE'
WHERE d.source_catalog_version='attendance-phase1'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

CREATE TABLE IF NOT EXISTS security.module_roles (
    module_key              varchar(80) NOT NULL,
    role_key                varchar(80) NOT NULL,
    display_name            varchar(160) NOT NULL,
    status                  varchar(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
    created_at_utc          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at_utc          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (module_key, role_key)
);

CREATE TABLE IF NOT EXISTS security.module_role_permissions (
    module_key              varchar(80) NOT NULL,
    role_key                varchar(80) NOT NULL,
    permission_key          varchar(160) NOT NULL REFERENCES security.permissions(permission_key),
    status                  varchar(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
    created_at_utc          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (module_key, role_key, permission_key),
    FOREIGN KEY (module_key, role_key) REFERENCES security.module_roles(module_key, role_key)
);

CREATE TABLE IF NOT EXISTS security.user_module_role_assignments (
    assignment_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               varchar(128) NOT NULL REFERENCES security.tenants(tenant_id),
    user_id                 varchar(160) NOT NULL REFERENCES security.users(user_id),
    module_key              varchar(80) NOT NULL,
    role_key                varchar(80) NOT NULL,
    status                  varchar(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE')),
    valid_from_utc          timestamptz,
    valid_to_utc            timestamptz,
    created_by_user_id      varchar(160),
    created_at_utc          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at_utc          timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (module_key, role_key) REFERENCES security.module_roles(module_key, role_key),
    CHECK (valid_to_utc IS NULL OR valid_from_utc IS NULL OR valid_to_utc > valid_from_utc)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_user_attendance_hradmin
ON security.user_module_role_assignments (tenant_id,user_id,module_key,role_key)
WHERE status='ACTIVE';

CREATE INDEX IF NOT EXISTS ix_user_module_roles_runtime
ON security.user_module_role_assignments (user_id,tenant_id,module_key,status);

INSERT INTO security.module_roles(module_key,role_key,display_name,status)
VALUES ('attendance','HRADMIN','HR Administrator','ACTIVE')
ON CONFLICT (module_key,role_key) DO UPDATE
SET display_name=EXCLUDED.display_name,status='ACTIVE',updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.module_role_permissions(module_key,role_key,permission_key,status)
SELECT 'attendance','HRADMIN',p.permission_key,'ACTIVE'
FROM security.permissions p
WHERE p.module_key='attendance' AND p.status='ACTIVE'
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE SET status='ACTIVE';

COMMIT;
