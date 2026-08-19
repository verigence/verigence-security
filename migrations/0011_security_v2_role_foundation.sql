-- Verigence Security v2 — Phase-1 RBAC foundation
-- Additive only. This migration does not migrate legacy role/group data and does not cut runtime authorization over to v2.

BEGIN;

CREATE TABLE IF NOT EXISTS security.role_definitions (
  role_key varchar(120) PRIMARY KEY,
  role_class varchar(20) NOT NULL
    CHECK (role_class IN ('OPERATING','ADMIN','TEST')),
  display_name varchar(180) NOT NULL,
  status varchar(20) NOT NULL
    CHECK (status IN ('ACTIVE','INACTIVE')),
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL
);

-- Fixed Phase-1 human role catalogue. This seeds role definitions only; it does not
-- seed role-permission bundles or migrate any existing USER role assignment.
INSERT INTO security.role_definitions
(role_key,role_class,display_name,status,created_at_utc,updated_at_utc)
VALUES
  ('PC','OPERATING','Process Consultant','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('TL','OPERATING','Team Lead','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('PM','OPERATING','Project Manager','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('CRM','OPERATING','CRM','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('Executive','OPERATING','Executive','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('TenantAdmin','ADMIN','Tenant Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('ModuleAdmin','ADMIN','Module Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('SuperAdmin','ADMIN','Super Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
  ('TestUser','TEST','Test User','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO NOTHING;

CREATE TABLE IF NOT EXISTS security.platform_role_permission_defaults (
  role_key varchar(120) NOT NULL
    REFERENCES security.role_definitions(role_key),
  permission_key varchar(180) NOT NULL
    REFERENCES security.permissions(permission_key),
  source_catalog_version varchar(40),
  status varchar(20) NOT NULL
    CHECK (status IN ('ACTIVE','INACTIVE')),
  created_at_utc timestamptz NOT NULL,
  PRIMARY KEY(role_key,permission_key)
);

CREATE TABLE IF NOT EXISTS security.tenant_role_permissions (
  tenant_id uuid NOT NULL
    REFERENCES security.tenants(tenant_id),
  role_key varchar(120) NOT NULL
    REFERENCES security.role_definitions(role_key),
  permission_key varchar(180) NOT NULL
    REFERENCES security.permissions(permission_key),
  assigned_by_user_id uuid NOT NULL
    REFERENCES security.users(user_id),
  assigned_at_utc timestamptz NOT NULL,
  PRIMARY KEY(tenant_id,role_key,permission_key)
);
CREATE INDEX IF NOT EXISTS ix_tenant_role_permissions_role
ON security.tenant_role_permissions(tenant_id,role_key);

CREATE TABLE IF NOT EXISTS security.user_tenant_operating_roles (
  assignment_id uuid PRIMARY KEY,
  user_id uuid NOT NULL
    REFERENCES security.users(user_id),
  tenant_id uuid NOT NULL
    REFERENCES security.tenants(tenant_id),
  role_key varchar(120) NOT NULL
    REFERENCES security.role_definitions(role_key),
  status varchar(20) NOT NULL
    CHECK (status IN ('ACTIVE','ENDED')),
  valid_from_utc timestamptz,
  valid_to_utc timestamptz,
  assigned_by_user_id uuid NOT NULL
    REFERENCES security.users(user_id),
  assigned_at_utc timestamptz NOT NULL,
  ended_at_utc timestamptz,
  CHECK (role_key IN ('PC','TL','PM','CRM','Executive')),
  CHECK (valid_to_utc IS NULL OR valid_from_utc IS NULL OR valid_to_utc > valid_from_utc)
);

-- Exactly one ACTIVE operating role per USER/Tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_v2_active_operating_role_user_tenant
ON security.user_tenant_operating_roles(user_id,tenant_id)
WHERE status='ACTIVE';

-- Exactly one ACTIVE PM per Tenant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_v2_active_pm_per_tenant
ON security.user_tenant_operating_roles(tenant_id)
WHERE status='ACTIVE' AND role_key='PM';

-- Supports role-aligned Group reads without introducing independent Group authorization.
CREATE INDEX IF NOT EXISTS ix_v2_operating_role_tenant_role
ON security.user_tenant_operating_roles(tenant_id,role_key)
WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS security.user_admin_role_assignments (
  assignment_id uuid PRIMARY KEY,
  user_id uuid NOT NULL
    REFERENCES security.users(user_id),
  role_key varchar(120) NOT NULL
    REFERENCES security.role_definitions(role_key),
  scope_type varchar(20) NOT NULL
    CHECK (scope_type IN ('PLATFORM','TENANT','MODULE')),
  scope_id varchar(180),
  status varchar(20) NOT NULL
    CHECK (status IN ('ACTIVE','ENDED')),
  assigned_by_user_id uuid
    REFERENCES security.users(user_id),
  assigned_at_utc timestamptz NOT NULL,
  ended_at_utc timestamptz,
  CHECK (role_key IN ('SuperAdmin','TenantAdmin','ModuleAdmin')),
  CHECK (
    (role_key='SuperAdmin' AND scope_type='PLATFORM' AND scope_id IS NULL)
    OR
    (role_key='TenantAdmin' AND scope_type='TENANT' AND scope_id IS NOT NULL)
    OR
    (role_key='ModuleAdmin' AND scope_type='MODULE' AND scope_id IS NOT NULL)
  )
);

-- Phase 1 allows exactly one ACTIVE SuperAdmin globally.
CREATE UNIQUE INDEX IF NOT EXISTS uq_v2_single_active_super_admin
ON security.user_admin_role_assignments(role_key)
WHERE status='ACTIVE' AND role_key='SuperAdmin';

CREATE UNIQUE INDEX IF NOT EXISTS uq_v2_active_tenant_admin_user_scope
ON security.user_admin_role_assignments(user_id,scope_id)
WHERE status='ACTIVE' AND role_key='TenantAdmin';

CREATE UNIQUE INDEX IF NOT EXISTS uq_v2_active_module_admin_user_scope
ON security.user_admin_role_assignments(user_id,scope_id)
WHERE status='ACTIVE' AND role_key='ModuleAdmin';

COMMIT;
