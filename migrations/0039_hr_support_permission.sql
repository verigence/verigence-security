-- Verigence Security v2: HR Feedback & Support. One permission, hr.support.manage, for answering and
-- closing the tickets employees raise. It is granted to no HR module role on purpose: SuperAdmin
-- passes it through its blanket access, so every ticket reaches SuperAdmin and nobody else.
-- Additive and idempotent.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
('hr.support.manage','hr','support','manage',NULL,'ACTIVE','hr.support.manage','hr-phase3',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key='hr',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='hr-phase3',
    updated_at_utc=CURRENT_TIMESTAMP;

COMMIT;
