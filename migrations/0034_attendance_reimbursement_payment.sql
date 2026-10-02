-- Attendance-only Finance payment-processing permission.
-- Additive only; no existing Verigence operating/admin roles are modified.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
(
  'attendance.reimbursement.payment.manage',
  'attendance',
  'reimbursement.payment',
  'manage',
  'Mark approved Employee reimbursements as processing/paid and capture payment details',
  'ACTIVE',
  'Process reimbursement payments',
  'attendance-employee-v2',
  CURRENT_TIMESTAMP
)
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  description=EXCLUDED.description,
  display_name=EXCLUDED.display_name,
  catalog_version=EXCLUDED.catalog_version,
  status='ACTIVE',
  updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.module_role_permissions
(module_key,role_key,permission_key,status,created_at_utc)
VALUES
(
  'attendance',
  'FINANCEADMIN',
  'attendance.reimbursement.payment.manage',
  'ACTIVE',
  CURRENT_TIMESTAMP
)
ON CONFLICT (module_key,role_key,permission_key)
DO UPDATE SET status='ACTIVE';

COMMIT;
