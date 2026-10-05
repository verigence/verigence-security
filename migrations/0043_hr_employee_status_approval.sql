-- Verigence Security v2: HR employee status changes (Active, Suspended, Terminated, Quit) are
-- requested by HR and approved by the CEO. One permission, hr.employee.status_approve, is held by the
-- CEO role alone; SuperAdmin does not get it through blanket access (see
-- SUPER_ADMIN_EXCLUDED_PERMISSIONS). Requesting a change needs the existing hr.employee.manage.
-- Additive and idempotent.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
('hr.employee.status_approve','hr','employee','status_approve',NULL,'ACTIVE','hr.employee.status_approve','hr-phase4',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key='hr',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='hr-phase4',
    updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
VALUES
('hr','CEO','hr.employee.status_approve','ACTIVE',CURRENT_TIMESTAMP)
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE
SET status='ACTIVE';

COMMIT;
