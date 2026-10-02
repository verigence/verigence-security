-- Verigence Security v2 — Employee/Attendance module permissions.
-- Additive only: no existing role, operating-role, admin-role or module-role behavior is altered.

BEGIN;

WITH new_permissions(permission_key,resource_key,action_key,description,display_name) AS (
  VALUES
    ('attendance.employee.manage','employee','manage',
     'Manage Employee/Attendance employee records and onboarding','Manage employees'),
    ('attendance.attendance.admin','attendance-admin','manage',
     'Administer Employee/Attendance records and corrections','Administer attendance'),
    ('attendance.leave.hr.approve','leave.hr','approve',
     'HR validation of employee leave requests','Validate leave as HR'),
    ('attendance.reimbursement.read','reimbursement','read',
     'Read Employee/Attendance reimbursement claims','Read reimbursement claims'),
    ('attendance.reimbursement.hr.approve','reimbursement.hr','approve',
     'HR approval of reimbursement claims','Approve reimbursements as HR'),
    ('attendance.reimbursement.finance.approve','reimbursement.finance','approve',
     'Finance approval of reimbursement claims when Finance review is required',
     'Approve reimbursements as Finance'),
    ('attendance.payroll.manage','payroll','manage',
     'Calculate, review and finalize Employee/Attendance payroll','Manage payroll'),
    ('attendance.report.read','employee-report','read',
     'Read Employee/Attendance reports','Read employee reports'),
    ('attendance.report.export','employee-report','export',
     'Export Employee/Attendance reports','Export employee reports'),
    ('attendance.config.manage','employee-config','manage',
     'Manage Employee/Attendance policy configuration','Manage employee configuration')
)
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
SELECT permission_key,'attendance',resource_key,action_key,description,'ACTIVE',
       display_name,'attendance-employee-v1',CURRENT_TIMESTAMP
FROM new_permissions
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  description=EXCLUDED.description,
  display_name=EXCLUDED.display_name,
  catalog_version=EXCLUDED.catalog_version,
  status='ACTIVE',
  updated_at_utc=CURRENT_TIMESTAMP;

-- Reuse the existing Attendance HRADMIN. It receives HR/employee administration
-- privileges, but deliberately does NOT receive Finance approval.
WITH hr_permissions(permission_key) AS (
  VALUES
    ('attendance.employee.manage'),
    ('attendance.attendance.admin'),
    ('attendance.leave.hr.approve'),
    ('attendance.reimbursement.read'),
    ('attendance.reimbursement.hr.approve'),
    ('attendance.payroll.manage'),
    ('attendance.report.read'),
    ('attendance.report.export')
)
INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
SELECT 'attendance','HRADMIN',permission_key,'ACTIVE',CURRENT_TIMESTAMP
FROM hr_permissions
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE SET status='ACTIVE';

-- FinanceAdmin is a secondary Attendance module role only.
INSERT INTO security.module_roles
(module_key,role_key,display_name,status,created_at_utc,updated_at_utc)
VALUES
('attendance','FINANCEADMIN','Finance Administrator','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (module_key,role_key) DO UPDATE SET
  display_name=EXCLUDED.display_name,
  status='ACTIVE',
  updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
VALUES
('attendance','FINANCEADMIN','attendance.reimbursement.read','ACTIVE',CURRENT_TIMESTAMP),
('attendance','FINANCEADMIN','attendance.reimbursement.finance.approve','ACTIVE',CURRENT_TIMESTAMP)
ON CONFLICT (module_key,role_key,permission_key) DO UPDATE SET status='ACTIVE';

COMMIT;
