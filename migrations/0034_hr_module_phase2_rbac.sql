-- Verigence Security v2: HR module permissions for attendance, leave, reimbursement and payroll.
-- Additive and idempotent. Extends the company-wide HR module roles from 0033. Team Lead and
-- Project Manager approvals do not use these: they come from a person's project role in Audit Core.

BEGIN;

WITH hr_permissions(permission_key,resource_key,action_key) AS (
  VALUES
    ('hr.attendance.read_all','attendance','read_all'),
    ('hr.leave.review','leave','review'),
    ('hr.claim.review','claim','review'),
    ('hr.claim.review_finance','claim','review_finance'),
    ('hr.salary.propose','salary','propose'),
    ('hr.salary.approve','salary','approve'),
    ('hr.payroll.read','payroll','read'),
    ('hr.payroll.prepare','payroll','prepare'),
    ('hr.payroll.approve','payroll','approve')
)
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
SELECT permission_key,'hr',resource_key,action_key,NULL,'ACTIVE',permission_key,
       'hr-phase2',CURRENT_TIMESTAMP
FROM hr_permissions
ON CONFLICT (permission_key) DO UPDATE
SET module_key='hr',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='hr-phase2',
    updated_at_utc=CURRENT_TIMESTAMP;

-- HRADMIN prepares and reviews; FINANCEADMIN approves salary structures and large or exceptional
-- claims; CEO holds every HR permission and alone approves a payroll run.
WITH grants(role_key,permission_key) AS (
  VALUES
    ('HRADMIN','hr.attendance.read_all'),
    ('HRADMIN','hr.leave.review'),
    ('HRADMIN','hr.claim.review'),
    ('HRADMIN','hr.salary.propose'),
    ('HRADMIN','hr.payroll.read'),
    ('HRADMIN','hr.payroll.prepare'),
    ('FINANCEADMIN','hr.claim.review_finance'),
    ('FINANCEADMIN','hr.salary.approve'),
    ('FINANCEADMIN','hr.payroll.read'),
    ('CEO','hr.attendance.read_all'),
    ('CEO','hr.leave.review'),
    ('CEO','hr.claim.review'),
    ('CEO','hr.claim.review_finance'),
    ('CEO','hr.salary.propose'),
    ('CEO','hr.salary.approve'),
    ('CEO','hr.payroll.read'),
    ('CEO','hr.payroll.prepare'),
    ('CEO','hr.payroll.approve')
)
INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
SELECT 'hr',role_key,permission_key,'ACTIVE',CURRENT_TIMESTAMP
FROM grants
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE
SET status='ACTIVE';

COMMIT;
