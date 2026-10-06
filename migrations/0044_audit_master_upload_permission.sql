-- Verigence Security v2: uploading the OEM price masters (price list, consumer scheme, exchange scheme,
-- corporate policy, discount grid) from the Web is open to the Team Lead and the Project Manager of a
-- project, as well as SuperAdmin. One permission, audit.master.upload, held by the TL and PM roles.
-- It is not part of the module-admin set, so it carries no write or publish authority over anything else.
-- Additive and idempotent: new projects get it from the platform defaults, existing projects are backfilled.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
VALUES
('audit.master.upload','audit','master','upload',NULL,'ACTIVE','audit.master.upload','audit-2.2',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key='audit',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='audit-2.2',
    updated_at_utc=CURRENT_TIMESTAMP;

INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
VALUES
('TL','audit.master.upload','audit-2.2','ACTIVE',CURRENT_TIMESTAMP),
('PM','audit.master.upload','audit-2.2','ACTIVE',CURRENT_TIMESTAMP)
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- every existing project's TL and PM role (the assigner is whoever assigned that role its master.read)
INSERT INTO security.tenant_role_permissions
(tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
SELECT DISTINCT ON (t.tenant_id,t.role_key)
       t.tenant_id,t.role_key,'audit.master.upload',t.assigned_by_user_id,CURRENT_TIMESTAMP
FROM security.tenant_role_permissions t
WHERE t.role_key IN ('TL','PM')
  AND t.permission_key='audit.master.read'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
