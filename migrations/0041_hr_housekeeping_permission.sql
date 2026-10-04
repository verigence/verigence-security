-- Verigence Security v2: HR housekeeping. One permission, hr.housekeeping.manage, for clearing old
-- attendance, leave and reimbursement records. It is granted to no HR module role on purpose: SuperAdmin
-- passes it through its blanket access, so only SuperAdmin can clear records.
-- Additive and idempotent.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
('hr.housekeeping.manage','hr','housekeeping','manage',NULL,'ACTIVE','hr.housekeeping.manage','hr-phase3',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key='hr',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='hr-phase3',
    updated_at_utc=CURRENT_TIMESTAMP;

COMMIT;
