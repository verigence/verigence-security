-- Verigence Security v2: HR access pauses. One permission, hr.access_pause.manage, for restoring a Team
-- Lead whom myHR paused for approvals left past the Monday 09:00 deadline. myHR has asked Security for
-- this key since the pause rule shipped, but it was never added to the catalog, so Security refused it to
-- everyone (SuperAdmin included) and the Access pauses tab in HR settings never showed.
-- Like housekeeping, it is granted to no HR module role on purpose: SuperAdmin passes it through its
-- blanket access, so only SuperAdmin can restore a paused person.
-- Additive and idempotent.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
('hr.access_pause.manage','hr','access_pause','manage',NULL,'ACTIVE','hr.access_pause.manage','hr-phase3',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key='hr',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='hr-phase3',
    updated_at_utc=CURRENT_TIMESTAMP;

COMMIT;
