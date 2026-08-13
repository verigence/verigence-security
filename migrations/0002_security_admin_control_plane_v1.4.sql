-- Verigence Security Admin Control Plane v1.4
-- Extends the immutable Security v1.3 baseline. UUIDs are application-generated.

BEGIN;

-- v1.4 permission catalogue metadata and lifecycle.
ALTER TABLE security.permissions
  ADD COLUMN IF NOT EXISTS display_name varchar(240),
  ADD COLUMN IF NOT EXISTS catalog_version varchar(40),
  ADD COLUMN IF NOT EXISTS updated_at_utc timestamptz;

ALTER TABLE security.permissions
  DROP CONSTRAINT IF EXISTS permissions_status_check;
ALTER TABLE security.permissions
  ADD CONSTRAINT permissions_status_check
  CHECK (status IN ('ACTIVE','DEPRECATED','RETIRED'));

-- Platform roles and local bootstrap authentication.
CREATE TABLE IF NOT EXISTS security.platform_roles (
  role_key varchar(120) PRIMARY KEY,
  role_name varchar(180) NOT NULL,
  description text,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','INACTIVE')),
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS security.platform_role_permissions (
  role_key varchar(120) NOT NULL REFERENCES security.platform_roles(role_key),
  permission_key varchar(180) NOT NULL REFERENCES security.permissions(permission_key),
  assigned_at_utc timestamptz NOT NULL,
  PRIMARY KEY(role_key,permission_key)
);

CREATE TABLE IF NOT EXISTS security.platform_user_role_assignments (
  assignment_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  role_key varchar(120) NOT NULL REFERENCES security.platform_roles(role_key),
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','ENDED')),
  assignment_source varchar(20) NOT NULL CHECK (assignment_source IN ('BOOTSTRAP','ADMIN')),
  assigned_by_user_id uuid REFERENCES security.users(user_id),
  assigned_at_utc timestamptz NOT NULL,
  ended_at_utc timestamptz,
  CHECK (
    (assignment_source='BOOTSTRAP' AND assigned_by_user_id IS NULL)
    OR (assignment_source='ADMIN' AND assigned_by_user_id IS NOT NULL)
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_platform_user_role
ON security.platform_user_role_assignments(user_id,role_key)
WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS security.local_user_credentials (
  credential_id uuid PRIMARY KEY,
  user_id uuid NOT NULL UNIQUE REFERENCES security.users(user_id),
  login_name varchar(320) NOT NULL UNIQUE,
  password_hash varchar(500) NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','REVOKED')),
  must_change_password boolean NOT NULL,
  password_changed_at_utc timestamptz,
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL
);

-- Module catalogue and role-template provenance.
CREATE TABLE IF NOT EXISTS security.modules (
  module_key varchar(40) PRIMARY KEY,
  module_name varchar(240) NOT NULL,
  catalog_version varchar(40) NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','INACTIVE')),
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL,
  updated_by_user_id uuid NOT NULL REFERENCES security.users(user_id)
);

CREATE TABLE IF NOT EXISTS security.module_role_templates (
  template_id uuid PRIMARY KEY,
  module_key varchar(40) NOT NULL REFERENCES security.modules(module_key),
  template_key varchar(180) NOT NULL,
  template_name varchar(240) NOT NULL,
  description text,
  catalog_version varchar(40) NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','DEPRECATED','RETIRED')),
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL,
  UNIQUE(module_key,template_key)
);

CREATE TABLE IF NOT EXISTS security.module_role_template_permissions (
  template_id uuid NOT NULL REFERENCES security.module_role_templates(template_id),
  permission_key varchar(180) NOT NULL REFERENCES security.permissions(permission_key),
  assigned_at_utc timestamptz NOT NULL,
  PRIMARY KEY(template_id,permission_key)
);

CREATE TABLE IF NOT EXISTS security.role_template_bindings (
  binding_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  role_id uuid NOT NULL,
  template_id uuid NOT NULL REFERENCES security.module_role_templates(template_id),
  applied_catalog_version varchar(40) NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('CURRENT','SUPERSEDED')),
  applied_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  applied_at_utc timestamptz NOT NULL,
  superseded_at_utc timestamptz,
  FOREIGN KEY(tenant_id,role_id) REFERENCES security.roles(tenant_id,role_id)
);

-- Tenant Groups. No nested Group relation exists by design.
CREATE TABLE IF NOT EXISTS security.groups (
  group_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  group_key varchar(120) NOT NULL,
  group_name varchar(240) NOT NULL,
  description text,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','INACTIVE')),
  created_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL,
  UNIQUE(tenant_id,group_key),
  UNIQUE(tenant_id,group_id)
);

CREATE TABLE IF NOT EXISTS security.group_memberships (
  group_membership_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  group_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','ENDED')),
  valid_from_utc timestamptz,
  valid_to_utc timestamptz,
  added_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  added_at_utc timestamptz NOT NULL,
  ended_at_utc timestamptz,
  FOREIGN KEY(tenant_id,group_id) REFERENCES security.groups(tenant_id,group_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_group_membership
ON security.group_memberships(tenant_id,group_id,user_id)
WHERE status='ACTIVE';

CREATE TABLE IF NOT EXISTS security.group_role_assignments (
  assignment_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  group_id uuid NOT NULL,
  role_id uuid NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','ENDED')),
  assigned_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  assigned_at_utc timestamptz NOT NULL,
  ended_at_utc timestamptz,
  FOREIGN KEY(tenant_id,group_id) REFERENCES security.groups(tenant_id,group_id),
  FOREIGN KEY(tenant_id,role_id) REFERENCES security.roles(tenant_id,role_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_group_role
ON security.group_role_assignments(tenant_id,group_id,role_id)
WHERE status='ACTIVE';

-- Invitation and privileged-access workflow persistence.
CREATE TABLE IF NOT EXISTS security.tenant_invitations (
  invitation_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  invited_user_id uuid NOT NULL REFERENCES security.users(user_id),
  invitee_email varchar(320),
  invitee_mobile varchar(40),
  employee_code varchar(120),
  acceptance_token_hash varchar(500) NOT NULL UNIQUE,
  proposed_access_json jsonb NOT NULL,
  requires_privileged_approval boolean NOT NULL,
  status varchar(20) NOT NULL
    CHECK (status IN ('PENDING','ACCEPTED','CANCELLED','EXPIRED','REJECTED')),
  invited_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  invited_at_utc timestamptz NOT NULL,
  expires_at_utc timestamptz NOT NULL,
  accepted_at_utc timestamptz,
  correlation_id varchar(128) NOT NULL,
  CHECK (expires_at_utc > invited_at_utc)
);

CREATE TABLE IF NOT EXISTS security.privileged_access_requests (
  request_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  subject_user_id uuid NOT NULL REFERENCES security.users(user_id),
  role_id uuid NOT NULL,
  source_invitation_id uuid REFERENCES security.tenant_invitations(invitation_id),
  status varchar(20) NOT NULL
    CHECK (status IN ('PENDING','APPROVED','REJECTED','CANCELLED','EXPIRED')),
  requested_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  requested_at_utc timestamptz NOT NULL,
  approved_by_user_id uuid REFERENCES security.users(user_id),
  decided_at_utc timestamptz,
  decision_reason text,
  correlation_id varchar(128) NOT NULL,
  FOREIGN KEY(tenant_id,role_id) REFERENCES security.roles(tenant_id,role_id),
  CHECK (approved_by_user_id IS NULL OR approved_by_user_id <> subject_user_id),
  CHECK (approved_by_user_id IS NULL OR approved_by_user_id <> requested_by_user_id)
);

CREATE TABLE IF NOT EXISTS security.admin_change_records (
  admin_change_id uuid PRIMARY KEY,
  correlation_id varchar(128) NOT NULL,
  scope_type varchar(20) NOT NULL CHECK (scope_type IN ('PLATFORM','TENANT')),
  tenant_id uuid REFERENCES security.tenants(tenant_id),
  actor_user_id uuid NOT NULL REFERENCES security.users(user_id),
  operation_key varchar(180) NOT NULL,
  resource_type varchar(120) NOT NULL,
  resource_id varchar(240),
  outcome varchar(20) NOT NULL CHECK (outcome IN ('SUCCESS','DENIED','FAILED')),
  before_state_json jsonb,
  after_state_json jsonb,
  occurred_at_utc timestamptz NOT NULL,
  CHECK (
    (scope_type='PLATFORM' AND tenant_id IS NULL)
    OR (scope_type='TENANT' AND tenant_id IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS ix_admin_change_correlation
ON security.admin_change_records(correlation_id);
CREATE INDEX IF NOT EXISTS ix_admin_change_tenant_time
ON security.admin_change_records(tenant_id,occurred_at_utc);

-- Configurable Security Control Registry.
CREATE TABLE IF NOT EXISTS security.security_control_definitions (
  control_key varchar(180) PRIMARY KEY,
  control_name varchar(240) NOT NULL,
  category varchar(20) NOT NULL CHECK (category IN ('USER_ACCESS','ADMIN','CORE')),
  parent_control_key varchar(180) REFERENCES security.security_control_definitions(control_key),
  configurable boolean NOT NULL,
  tenant_override_supported boolean NOT NULL,
  default_enabled boolean NOT NULL,
  description text NOT NULL,
  introduced_version varchar(40) NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','RETIRED')),
  sort_order integer NOT NULL
);

CREATE TABLE IF NOT EXISTS security.platform_security_control_settings (
  control_key varchar(180) PRIMARY KEY
    REFERENCES security.security_control_definitions(control_key),
  enabled boolean NOT NULL,
  configuration_version bigint NOT NULL CHECK (configuration_version >= 1),
  updated_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  updated_at_utc timestamptz NOT NULL,
  change_reason text NOT NULL CHECK (length(trim(change_reason)) > 0)
);

CREATE TABLE IF NOT EXISTS security.tenant_security_control_overrides (
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  control_key varchar(180) NOT NULL
    REFERENCES security.security_control_definitions(control_key),
  override_mode varchar(20) NOT NULL
    CHECK (override_mode IN ('INHERIT','ENABLED','DISABLED')),
  configuration_version bigint NOT NULL CHECK (configuration_version >= 1),
  updated_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  updated_at_utc timestamptz NOT NULL,
  change_reason text NOT NULL CHECK (length(trim(change_reason)) > 0),
  PRIMARY KEY(tenant_id,control_key)
);

-- Token-gated self-onboarding. Token material is hash-only.
CREATE TABLE IF NOT EXISTS security.tenant_self_onboarding_settings (
  tenant_id uuid PRIMARY KEY REFERENCES security.tenants(tenant_id),
  token_hash varchar(500) NOT NULL,
  token_version bigint NOT NULL CHECK (token_version >= 1),
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','DISABLED')),
  created_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  created_at_utc timestamptz NOT NULL,
  updated_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
  updated_at_utc timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS security.self_onboarding_requests (
  self_onboarding_request_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id),
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  external_identity_id uuid NOT NULL
    REFERENCES security.external_identities(external_identity_id),
  status varchar(32) NOT NULL
    CHECK (status IN ('PENDING_ADMIN_APPROVAL','APPROVED','REJECTED','CANCELLED')),
  submitted_at_utc timestamptz NOT NULL,
  submitted_source_ip inet NOT NULL,
  reviewed_by_user_id uuid REFERENCES security.users(user_id),
  reviewed_at_utc timestamptz,
  review_reason text,
  correlation_id varchar(128) NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_open_self_onboarding_request
ON security.self_onboarding_requests(tenant_id,user_id)
WHERE status IN ('PENDING_ADMIN_APPROVAL','APPROVED');

-- Canonical Security Admin v1.4 permission catalogue.
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,
 display_name,catalog_version,updated_at_utc)
VALUES
('security.platform_admin.read','security','platform_admin','read',NULL,'ACTIVE',
 'Read Platform Administrators','1.4',CURRENT_TIMESTAMP),
('security.platform_admin.manage','security','platform_admin','manage',NULL,'ACTIVE',
 'Manage Platform Administrators','1.4',CURRENT_TIMESTAMP),
('security.security_config.read','security','security_config','read',NULL,'ACTIVE',
 'Read Platform Security Configuration','1.4',CURRENT_TIMESTAMP),
('security.security_config.manage','security','security_config','manage',NULL,'ACTIVE',
 'Manage Platform Security Configuration','1.4',CURRENT_TIMESTAMP),
('security.tenant.create','security','tenant','create',NULL,'ACTIVE',
 'Create Tenant','1.4',CURRENT_TIMESTAMP),
('security.tenant.read','security','tenant','read',NULL,'ACTIVE',
 'Read Tenant','1.4',CURRENT_TIMESTAMP),
('security.tenant.update','security','tenant','update',NULL,'ACTIVE',
 'Update Tenant','1.4',CURRENT_TIMESTAMP),
('security.tenant.suspend','security','tenant','suspend',NULL,'ACTIVE',
 'Suspend Tenant','1.4',CURRENT_TIMESTAMP),
('security.tenant.activate','security','tenant','activate',NULL,'ACTIVE',
 'Activate Tenant','1.4',CURRENT_TIMESTAMP),
('security.tenant.bootstrap_admin','security','tenant','bootstrap_admin',NULL,'ACTIVE',
 'Bootstrap Tenant Administrator','1.4',CURRENT_TIMESTAMP),
('security.module.read','security','module','read',NULL,'ACTIVE',
 'Read Module Catalogue','1.4',CURRENT_TIMESTAMP),
('security.module.manage','security','module','manage',NULL,'ACTIVE',
 'Manage Module Catalogue','1.4',CURRENT_TIMESTAMP),
('security.permission.read','security','permission','read',NULL,'ACTIVE',
 'Read Permission Catalogue','1.4',CURRENT_TIMESTAMP),
('security.audit.read','security','audit','read',NULL,'ACTIVE',
 'Read Security Audit','1.4',CURRENT_TIMESTAMP),
('security.member.read','security','member','read',NULL,'ACTIVE',
 'Read Tenant Members','1.4',CURRENT_TIMESTAMP),
('security.member.invite','security','member','invite',NULL,'ACTIVE',
 'Invite Tenant Member','1.4',CURRENT_TIMESTAMP),
('security.member.update','security','member','update',NULL,'ACTIVE',
 'Update Tenant Member','1.4',CURRENT_TIMESTAMP),
('security.member.suspend','security','member','suspend',NULL,'ACTIVE',
 'Suspend Tenant Member','1.4',CURRENT_TIMESTAMP),
('security.member.end','security','member','end',NULL,'ACTIVE',
 'End Tenant Membership','1.4',CURRENT_TIMESTAMP),
('security.member.approve','security','member','approve',NULL,'ACTIVE',
 'Approve Tenant Member','1.4',CURRENT_TIMESTAMP),
('security.group.read','security','group','read',NULL,'ACTIVE',
 'Read Tenant Groups','1.4',CURRENT_TIMESTAMP),
('security.group.create','security','group','create',NULL,'ACTIVE',
 'Create Tenant Group','1.4',CURRENT_TIMESTAMP),
('security.group.update','security','group','update',NULL,'ACTIVE',
 'Update Tenant Group','1.4',CURRENT_TIMESTAMP),
('security.group.assign','security','group','assign',NULL,'ACTIVE',
 'Assign Tenant Group Membership and Roles','1.4',CURRENT_TIMESTAMP),
('security.role.read','security','role','read',NULL,'ACTIVE',
 'Read Tenant Roles','1.4',CURRENT_TIMESTAMP),
('security.role.create','security','role','create',NULL,'ACTIVE',
 'Create Tenant Role','1.4',CURRENT_TIMESTAMP),
('security.role.update','security','role','update',NULL,'ACTIVE',
 'Update Tenant Role','1.4',CURRENT_TIMESTAMP),
('security.role.assign','security','role','assign',NULL,'ACTIVE',
 'Assign Tenant Role','1.4',CURRENT_TIMESTAMP),
('security.location.read','security','location','read',NULL,'ACTIVE',
 'Read Tenant Locations','1.4',CURRENT_TIMESTAMP),
('security.location.create','security','location','create',NULL,'ACTIVE',
 'Create Tenant Location','1.4',CURRENT_TIMESTAMP),
('security.location.update','security','location','update',NULL,'ACTIVE',
 'Update Tenant Location','1.4',CURRENT_TIMESTAMP),
('security.location.assign','security','location','assign',NULL,'ACTIVE',
 'Assign Tenant Location','1.4',CURRENT_TIMESTAMP),
('security.schedule.read','security','schedule','read',NULL,'ACTIVE',
 'Read Access Schedules','1.4',CURRENT_TIMESTAMP),
('security.schedule.create','security','schedule','create',NULL,'ACTIVE',
 'Create Access Schedule','1.4',CURRENT_TIMESTAMP),
('security.schedule.update','security','schedule','update',NULL,'ACTIVE',
 'Update Access Schedule','1.4',CURRENT_TIMESTAMP),
('security.device.read','security','device','read',NULL,'ACTIVE',
 'Read Registered Devices','1.4',CURRENT_TIMESTAMP),
('security.device.approve','security','device','approve',NULL,'ACTIVE',
 'Approve Registered Device','1.4',CURRENT_TIMESTAMP),
('security.device.block','security','device','block',NULL,'ACTIVE',
 'Block Registered Device','1.4',CURRENT_TIMESTAMP),
('security.device.revoke','security','device','revoke',NULL,'ACTIVE',
 'Revoke Registered Device','1.4',CURRENT_TIMESTAMP),
('security.policy.read','security','policy','read',NULL,'ACTIVE',
 'Read Tenant Security Policy','1.4',CURRENT_TIMESTAMP),
('security.policy.update','security','policy','update',NULL,'ACTIVE',
 'Update Tenant Security Policy','1.4',CURRENT_TIMESTAMP),
('security.retention.read','security','retention','read',NULL,'ACTIVE',
 'Read Security Retention Policy','1.4',CURRENT_TIMESTAMP),
('security.retention.update','security','retention','update',NULL,'ACTIVE',
 'Update Security Retention Policy','1.4',CURRENT_TIMESTAMP),
('security.privileged_access.approve','security','privileged_access','approve',NULL,
 'ACTIVE','Approve Privileged Access','1.4',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  display_name=EXCLUDED.display_name,
  catalog_version=EXCLUDED.catalog_version,
  status=EXCLUDED.status,
  updated_at_utc=EXCLUDED.updated_at_utc;

-- Standard Platform roles.
INSERT INTO security.platform_roles
(role_key,role_name,description,status,created_at_utc,updated_at_utc)
VALUES
('platform.super_admin','Platform Super Admin',
 'Highest Security control-plane authority','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
('platform.security_admin','Platform Security Admin',
 'Security platform configuration and security operations',
 'ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
('platform.module_catalog_admin','Module Catalog Admin',
 'Module, permission and role-template catalogue administration',
 'ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
('platform.auditor','Platform Auditor',
 'Read-only Platform and cross-Tenant Security audit visibility',
 'ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO UPDATE SET
  role_name=EXCLUDED.role_name,
  description=EXCLUDED.description,
  status=EXCLUDED.status,
  updated_at_utc=EXCLUDED.updated_at_utc;

-- Exact Platform role permission bundles.
DELETE FROM security.platform_role_permissions
WHERE role_key IN (
  'platform.super_admin',
  'platform.security_admin',
  'platform.module_catalog_admin',
  'platform.auditor'
);

INSERT INTO security.platform_role_permissions
(role_key,permission_key,assigned_at_utc)
SELECT 'platform.super_admin', permission_key, CURRENT_TIMESTAMP
FROM security.permissions
WHERE permission_key IN (
  'security.platform_admin.read',
  'security.platform_admin.manage',
  'security.security_config.read',
  'security.security_config.manage',
  'security.tenant.create',
  'security.tenant.read',
  'security.tenant.update',
  'security.tenant.suspend',
  'security.tenant.activate',
  'security.tenant.bootstrap_admin',
  'security.module.read',
  'security.module.manage',
  'security.permission.read',
  'security.audit.read'
);

INSERT INTO security.platform_role_permissions
(role_key,permission_key,assigned_at_utc)
SELECT 'platform.security_admin', permission_key, CURRENT_TIMESTAMP
FROM security.permissions
WHERE permission_key IN (
  'security.security_config.read',
  'security.security_config.manage',
  'security.platform_admin.read',
  'security.tenant.read',
  'security.audit.read'
);

INSERT INTO security.platform_role_permissions
(role_key,permission_key,assigned_at_utc)
SELECT 'platform.module_catalog_admin', permission_key, CURRENT_TIMESTAMP
FROM security.permissions
WHERE permission_key IN (
  'security.module.read',
  'security.module.manage',
  'security.permission.read',
  'security.audit.read'
);

INSERT INTO security.platform_role_permissions
(role_key,permission_key,assigned_at_utc)
SELECT 'platform.auditor', permission_key, CURRENT_TIMESTAMP
FROM security.permissions
WHERE permission_key IN (
  'security.platform_admin.read',
  'security.security_config.read',
  'security.tenant.read',
  'security.module.read',
  'security.permission.read',
  'security.audit.read'
);

-- Security Control Registry definitions. Definitions are product-owned, not Admin-created.
INSERT INTO security.security_control_definitions
(control_key,control_name,category,parent_control_key,configurable,
 tenant_override_supported,default_enabled,description,introduced_version,status,sort_order)
VALUES
('user_access.device_enforcement','Device Enforcement','USER_ACCESS',NULL,true,true,true,
 'Registered-device status and approval enforcement','1.4','ACTIVE',10),
('user_access.device_limit','Active Device Limit','USER_ACCESS',
 'user_access.device_enforcement',true,true,true,
 'Tenant active-device limit enforcement','1.4','ACTIVE',20),
('user_access.geo_enforcement','Geo Enforcement','USER_ACCESS',NULL,true,true,true,
 'Geo access-policy enforcement','1.4','ACTIVE',30),
('user_access.geo_freshness','Geo Freshness','USER_ACCESS',
 'user_access.geo_enforcement',true,true,true,
 'Geo age/freshness enforcement','1.4','ACTIVE',40),
('user_access.geo_accuracy','Geo Accuracy','USER_ACCESS',
 'user_access.geo_enforcement',true,true,true,
 'Geo accuracy threshold enforcement','1.4','ACTIVE',50),
('user_access.geo_integrity','Geo Integrity','USER_ACCESS',
 'user_access.geo_enforcement',true,true,true,
 'Geo integrity and spoof-signal enforcement','1.4','ACTIVE',60),
('user_access.geo_radius','Geo Radius','USER_ACCESS',
 'user_access.geo_enforcement',true,true,true,
 'Approved-location radius enforcement','1.4','ACTIVE',70),
('user_access.schedule_enforcement','Schedule Enforcement','USER_ACCESS',NULL,true,true,true,
 'Access schedule enforcement','1.4','ACTIVE',80),
('user_access.network_risk_enforcement','Network Risk Enforcement','USER_ACCESS',NULL,
 true,true,true,'Network and VPN risk enforcement','1.4','ACTIVE',90),
('user_access.refresh_geo_revalidation','Refresh Geo Revalidation','USER_ACCESS',
 'user_access.geo_enforcement',true,true,true,
 'Fresh geo revalidation during USER session refresh','1.4','ACTIVE',100),
('admin.privileged_access_approval','Privileged Access Approval','ADMIN',NULL,
 true,true,true,'Maker-checker enforcement for privileged Tenant roles','1.4','ACTIVE',110),
('admin.self_onboarding','Self Onboarding','ADMIN',NULL,true,true,false,
 'Tenant token-gated self-onboarding endpoint','1.4','ACTIVE',120),
('core.identity_verification','Identity Verification','CORE',NULL,false,false,true,
 'External identity verification remains mandatory','1.4','ACTIVE',200),
('core.token_signature_validation','Token Signature Validation','CORE',NULL,false,false,true,
 'Security token signatures remain mandatory','1.4','ACTIVE',210),
('core.token_issuer_audience_validation','Token Issuer Audience Validation','CORE',NULL,
 false,false,true,'Issuer and audience validation remains mandatory','1.4','ACTIVE',220),
('core.actor_type_validation','Actor Type Validation','CORE',NULL,false,false,true,
 'Actor type validation remains mandatory','1.4','ACTIVE',230),
('core.principal_status_validation','Principal Status Validation','CORE',NULL,false,false,true,
 'Principal status validation remains mandatory','1.4','ACTIVE',240),
('core.tenant_isolation','Tenant Isolation','CORE',NULL,false,false,true,
 'Cross-Tenant isolation remains mandatory','1.4','ACTIVE',250),
('core.tenant_membership_validation','Tenant Membership Validation','CORE',NULL,false,false,true,
 'Active Tenant membership remains mandatory','1.4','ACTIVE',260),
('core.rbac_permission_enforcement','RBAC Permission Enforcement','CORE',NULL,false,false,true,
 'Required-permission enforcement remains mandatory','1.4','ACTIVE',270),
('core.token_expiry','Token Expiry','CORE',NULL,false,false,true,
 'Bounded token expiry remains mandatory','1.4','ACTIVE',280),
('core.admin_audit','Admin Audit','CORE',NULL,false,false,true,
 'Administrative audit remains mandatory','1.4','ACTIVE',290),
('core.onboarding_human_acceptance','Onboarding Human Acceptance','CORE',NULL,
 false,false,true,'Human onboarding acceptance remains mandatory','1.4','ACTIVE',300),
('core.secret_hashing','Secret Hashing','CORE',NULL,false,false,true,
 'Credential and onboarding secret hashing remains mandatory','1.4','ACTIVE',310)
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
