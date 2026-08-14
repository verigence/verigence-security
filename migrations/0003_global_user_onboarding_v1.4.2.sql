-- Verigence Security — Global User Onboarding v1.4.2
-- Supersedes Tenant-scoped human onboarding as an active runtime model.
-- Existing Tenant onboarding/membership tables are retained as migration/history debt only.

BEGIN;

-- Global USER lifecycle. INVITED remains for historical compatibility; PENDING is the
-- canonical state for a newly accepted Verigence onboarding request until Security Admin approval.
ALTER TABLE security.users
  DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE security.users
  ADD CONSTRAINT users_status_check
  CHECK (status IN ('PENDING','INVITED','ACTIVE','SUSPENDED','DISABLED','EXITED'));

-- One Platform-scoped onboarding key. The hash is used for validation; encrypted material is
-- retained so an authorized Platform Super Admin / Security Admin can reveal and share the key.
CREATE TABLE IF NOT EXISTS security.platform_user_onboarding_settings (
  singleton_id smallint PRIMARY KEY DEFAULT 1 CHECK (singleton_id = 1),
  key_hash varchar(500) NOT NULL,
  key_ciphertext text NOT NULL,
  key_version bigint NOT NULL CHECK (key_version >= 1),
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','DISABLED')),
  created_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  created_at_utc timestamptz NOT NULL,
  updated_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  updated_at_utc timestamptz NOT NULL
);

-- One-time, Platform-global human onboarding workflow. No Tenant identifier appears here.
CREATE TABLE IF NOT EXISTS security.platform_user_onboarding_requests (
  onboarding_request_id uuid PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE REFERENCES security.users(user_id),
  email varchar(320) NOT NULL,
  clerk_invitation_id varchar(240),
  clerk_user_id varchar(240),
  status varchar(40) NOT NULL CHECK (
    status IN (
      'PENDING_CLERK',
      'CLERK_INVITED',
      'PENDING_ADMIN_APPROVAL',
      'APPROVED',
      'REJECTED',
      'CANCELLED',
      'CLERK_PROVISIONING_FAILED'
    )
  ),
  submitted_source_ip inet NOT NULL,
  submitted_at_utc timestamptz NOT NULL,
  reviewed_by_user_id uuid REFERENCES security.users(user_id),
  reviewed_at_utc timestamptz,
  review_reason text,
  correlation_id varchar(128) NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_platform_user_onboarding_status_time
ON security.platform_user_onboarding_requests(status,submitted_at_utc);

-- Security USER email is a global identity locator for the initial email-based Clerk invitation
-- flow. Clerk's immutable user ID remains the external authentication subject after binding.
CREATE UNIQUE INDEX IF NOT EXISTS uq_security_users_primary_email_ci
ON security.users ((lower(primary_email)))
WHERE primary_email IS NOT NULL;

-- Tenant authorization state replaces Tenant membership as the runtime authorization-version
-- carrier. This row is not membership and does not grant access by itself.
CREATE TABLE IF NOT EXISTS security.user_tenant_authorization_state (
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  authorization_version bigint NOT NULL DEFAULT 1 CHECK (authorization_version >= 1),
  updated_at_utc timestamptz NOT NULL,
  PRIMARY KEY(user_id,tenant_id)
);

-- Preserve authorization-version continuity for already-populated DEV data.
INSERT INTO security.user_tenant_authorization_state
(user_id,tenant_id,authorization_version,updated_at_utc)
SELECT user_id,tenant_id,GREATEST(authorization_version,1),updated_at_utc
FROM security.tenant_memberships
ON CONFLICT (user_id,tenant_id) DO UPDATE SET
  authorization_version=GREATEST(
    security.user_tenant_authorization_state.authorization_version,
    EXCLUDED.authorization_version
  ),
  updated_at_utc=GREATEST(
    security.user_tenant_authorization_state.updated_at_utc,
    EXCLUDED.updated_at_utc
  );

INSERT INTO security.user_tenant_authorization_state
(user_id,tenant_id,authorization_version,updated_at_utc)
SELECT DISTINCT user_id,tenant_id,1,CURRENT_TIMESTAMP
FROM security.user_role_assignments
ON CONFLICT (user_id,tenant_id) DO NOTHING;

INSERT INTO security.user_tenant_authorization_state
(user_id,tenant_id,authorization_version,updated_at_utc)
SELECT DISTINCT user_id,tenant_id,1,CURRENT_TIMESTAMP
FROM security.group_memberships
ON CONFLICT (user_id,tenant_id) DO NOTHING;

-- The v1.4 role-template upgrade route predates the authorization-state table. Keep token
-- invalidation correct for global USERs even when no historical tenant_memberships row exists.
CREATE OR REPLACE FUNCTION security.bump_template_authz_state_v1_4_2()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO security.user_tenant_authorization_state
  (user_id,tenant_id,authorization_version,updated_at_utc)
  SELECT affected.user_id,NEW.tenant_id,2,CURRENT_TIMESTAMP
  FROM (
    SELECT ura.user_id
    FROM security.user_role_assignments ura
    JOIN security.users u ON u.user_id=ura.user_id AND u.status='ACTIVE'
    WHERE ura.tenant_id=NEW.tenant_id
      AND ura.role_id=NEW.role_id
      AND ura.status='ACTIVE'
    UNION
    SELECT gm.user_id
    FROM security.group_role_assignments gra
    JOIN security.groups g
      ON g.tenant_id=gra.tenant_id AND g.group_id=gra.group_id AND g.status='ACTIVE'
    JOIN security.group_memberships gm
      ON gm.tenant_id=g.tenant_id AND gm.group_id=g.group_id AND gm.status='ACTIVE'
    JOIN security.users u ON u.user_id=gm.user_id AND u.status='ACTIVE'
    WHERE gra.tenant_id=NEW.tenant_id
      AND gra.role_id=NEW.role_id
      AND gra.status='ACTIVE'
  ) AS affected
  ON CONFLICT (user_id,tenant_id) DO UPDATE SET
    authorization_version=
      security.user_tenant_authorization_state.authorization_version+1,
    updated_at_utc=EXCLUDED.updated_at_utc;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_role_template_authz_v1_4_2
ON security.role_template_bindings;
CREATE TRIGGER trg_role_template_authz_v1_4_2
AFTER INSERT ON security.role_template_bindings
FOR EACH ROW
WHEN (NEW.status='CURRENT')
EXECUTE FUNCTION security.bump_template_authz_state_v1_4_2();

-- v1.3 access_sessions carried Tenant membership_id for USER sessions. v1.4.2 removes that
-- runtime requirement while retaining the nullable column for historical records.
DO $$
DECLARE
  constraint_name text;
BEGIN
  FOR constraint_name IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid=c.conrelid
    JOIN pg_namespace n ON n.oid=t.relnamespace
    WHERE n.nspname='security'
      AND t.relname='access_sessions'
      AND c.contype='c'
      AND pg_get_constraintdef(c.oid) ILIKE '%membership_id IS NOT NULL%'
  LOOP
    EXECUTE format('ALTER TABLE security.access_sessions DROP CONSTRAINT %I', constraint_name);
  END LOOP;
END $$;

ALTER TABLE security.access_sessions
  DROP CONSTRAINT IF EXISTS access_sessions_actor_shape_v1_4_2_check;
ALTER TABLE security.access_sessions
  ADD CONSTRAINT access_sessions_actor_shape_v1_4_2_check CHECK (
    (actor_type='USER' AND device_id IS NOT NULL AND location_id IS NOT NULL AND credential_id IS NULL)
    OR
    (actor_type IN ('SYSTEM','SERVICE_INTEGRATION') AND membership_id IS NULL
      AND device_id IS NULL AND location_id IS NULL AND credential_id IS NOT NULL)
  );

-- Platform-level USER lifecycle and onboarding permissions.
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,
 display_name,catalog_version,updated_at_utc)
VALUES
('security.user.read','security','user','read',
 'Read the Platform-global Verigence USER registry','ACTIVE',
 'Read Global Users','1.4.2',CURRENT_TIMESTAMP),
('security.user.manage','security','user','manage',
 'Approve and change Platform-global Verigence USER lifecycle status','ACTIVE',
 'Manage Global Users','1.4.2',CURRENT_TIMESTAMP),
('security.user_onboarding.read','security','user_onboarding','read',
 'Read Platform-global onboarding configuration and requests','ACTIVE',
 'Read Global User Onboarding','1.4.2',CURRENT_TIMESTAMP),
('security.user_onboarding.manage','security','user_onboarding','manage',
 'Manage the Platform-global onboarding key and onboarding workflow','ACTIVE',
 'Manage Global User Onboarding','1.4.2',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  description=EXCLUDED.description,
  status=EXCLUDED.status,
  display_name=EXCLUDED.display_name,
  catalog_version=EXCLUDED.catalog_version,
  updated_at_utc=EXCLUDED.updated_at_utc;

INSERT INTO security.platform_role_permissions(role_key,permission_key,assigned_at_utc)
SELECT role_key,permission_key,CURRENT_TIMESTAMP
FROM (
  VALUES
    ('platform.super_admin','security.user.read'),
    ('platform.super_admin','security.user.manage'),
    ('platform.super_admin','security.user_onboarding.read'),
    ('platform.super_admin','security.user_onboarding.manage'),
    ('platform.security_admin','security.user.read'),
    ('platform.security_admin','security.user.manage'),
    ('platform.security_admin','security.user_onboarding.read'),
    ('platform.security_admin','security.user_onboarding.manage'),
    ('platform.auditor','security.user.read'),
    ('platform.auditor','security.user_onboarding.read')
) AS grants(role_key,permission_key)
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- Retire the Tenant self-onboarding and membership-validation controls from the active model.
UPDATE security.security_control_definitions
SET status='RETIRED',
    description='Retired by v1.4.2: human onboarding is Platform-global, not Tenant-scoped'
WHERE control_key='admin.self_onboarding';

UPDATE security.security_control_definitions
SET status='RETIRED',
    description='Retired by v1.4.2: Tenant membership is not a runtime USER-access prerequisite'
WHERE control_key='core.tenant_membership_validation';

INSERT INTO security.security_control_definitions
(control_key,control_name,category,parent_control_key,configurable,
 tenant_override_supported,default_enabled,description,introduced_version,status,sort_order)
VALUES
('admin.global_user_onboarding','Global User Onboarding','ADMIN',NULL,true,false,true,
 'Platform-global one-time human onboarding controlled by Security','1.4.2','ACTIVE',120),
('core.user_status_validation','Global User Status Validation','CORE',NULL,false,false,true,
 'Security USER status must be ACTIVE before Verigence access is issued','1.4.2','ACTIVE',255),
('core.tenant_authorization_state','Tenant Authorization State','CORE',NULL,false,false,true,
 'Per-user/per-Tenant authorization versioning without Tenant membership','1.4.2','ACTIVE',265)
ON CONFLICT (control_key) DO UPDATE SET
  control_name=EXCLUDED.control_name,
  category=EXCLUDED.category,
  parent_control_key=EXCLUDED.parent_control_key,
  configurable=EXCLUDED.configurable,
  tenant_override_supported=EXCLUDED.tenant_override_supported,
  default_enabled=EXCLUDED.default_enabled,
  description=EXCLUDED.description,
  introduced_version=EXCLUDED.introduced_version,
  status=EXCLUDED.status,
  sort_order=EXCLUDED.sort_order;

COMMIT;
