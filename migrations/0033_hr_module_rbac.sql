-- Verigence Security v2: HR module permissions and global module roles (HRADMIN, FINANCEADMIN, CEO).
-- Additive and idempotent. Reuses the module_roles / module_role_permissions / global assignment
-- tables from 0027 and 0028. HR roles are company-wide: no Tenant or Project scope. The existing
-- `attendance` module and its HRADMIN role are untouched until the old PC attendance is retired.

BEGIN;

WITH hr_permissions(permission_key,resource_key,action_key) AS (
  VALUES
    ('hr.employee.read','employee','read'),
    ('hr.employee.manage','employee','manage'),
    ('hr.sensitive.read','sensitive','read'),
    ('hr.audit.read','audit','read'),
    ('hr.settings.manage','settings','manage')
)
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
SELECT permission_key,'hr',resource_key,action_key,NULL,'ACTIVE',permission_key,
       'hr-phase1',CURRENT_TIMESTAMP
FROM hr_permissions
ON CONFLICT (permission_key) DO UPDATE
SET module_key='hr',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='hr-phase1',
    updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.module_roles
(module_key,role_key,display_name,status,created_at_utc,updated_at_utc)
VALUES
('hr','HRADMIN','HR Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
('hr','FINANCEADMIN','Finance Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP),
('hr','CEO','Chief Executive Officer','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (module_key,role_key) DO UPDATE
SET display_name=EXCLUDED.display_name,
    status='ACTIVE',
    updated_at_utc=CURRENT_TIMESTAMP;

-- HRADMIN runs employee administration; FINANCEADMIN may see employees (payroll and claim approval
-- permissions arrive with those features); CEO holds every HR permission.
WITH grants(role_key,permission_key) AS (
  VALUES
    ('HRADMIN','hr.employee.read'),
    ('HRADMIN','hr.employee.manage'),
    ('HRADMIN','hr.sensitive.read'),
    ('HRADMIN','hr.audit.read'),
    ('HRADMIN','hr.settings.manage'),
    ('FINANCEADMIN','hr.employee.read'),
    ('CEO','hr.employee.read'),
    ('CEO','hr.employee.manage'),
    ('CEO','hr.sensitive.read'),
    ('CEO','hr.audit.read'),
    ('CEO','hr.settings.manage')
)
INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
SELECT 'hr',role_key,permission_key,'ACTIVE',CURRENT_TIMESTAMP
FROM grants
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE
SET status='ACTIVE';

COMMIT;
