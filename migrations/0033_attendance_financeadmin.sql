-- Verigence Security v2 — Attendance-only reimbursement approval roles/permissions.
-- Additive only: no existing role, operating-role, admin-role or module-role behavior is altered.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
('attendance.reimbursement.read','attendance','reimbursement','read',
 'Read Attendance reimbursement claims','ACTIVE',
 'Read reimbursement claims','attendance-employee-v1',CURRENT_TIMESTAMP),
('attendance.reimbursement.hr.approve','attendance','reimbursement.hr','approve',
 'HR approval of Attendance reimbursement claims','ACTIVE',
 'Approve reimbursements as HR','attendance-employee-v1',CURRENT_TIMESTAMP),
('attendance.reimbursement.finance.approve','attendance','reimbursement.finance','approve',
 'Finance approval of Attendance reimbursement claims when Finance review is required','ACTIVE',
 'Approve reimbursements as Finance','attendance-employee-v1',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  description=EXCLUDED.description,
  display_name=EXCLUDED.display_name,
  catalog_version=EXCLUDED.catalog_version,
  status='ACTIVE',
  updated_at_utc=CURRENT_TIMESTAMP;

-- Existing Attendance HRADMIN is reused. It receives HR reimbursement read/approval,
-- but deliberately does NOT receive the Finance approval permission.
INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
VALUES
('attendance','HRADMIN','attendance.reimbursement.read','ACTIVE',CURRENT_TIMESTAMP),
('attendance','HRADMIN','attendance.reimbursement.hr.approve','ACTIVE',CURRENT_TIMESTAMP)
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
