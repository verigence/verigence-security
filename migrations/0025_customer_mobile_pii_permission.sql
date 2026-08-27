-- Customer mobile PII disclosure permission
-- Project-owner approved 2026-08-27.
-- The permission controls full contact disclosure only; ordinary Customer access
-- and Tenant/business scope remain separately authorized.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,
 display_name,catalog_version,updated_at_utc)
VALUES
('audit.customer.contact.full.read','audit','customer.contact.full','read',
 'Read complete customer contact PII within otherwise permitted Customer scope',
 'ACTIVE','Read complete customer contact PII','audit-2.2',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE
SET module_key=EXCLUDED.module_key,
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    description=EXCLUDED.description,
    display_name=EXCLUDED.display_name,
    catalog_version=EXCLUDED.catalog_version,
    status='ACTIVE',
    updated_at_utc=CURRENT_TIMESTAMP;

-- Future Tenant role-bundle seeding: Executive receives the permission by default.
-- PC/TL/PM/CRM are intentionally not granted this permission.
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
VALUES
('Executive','audit.customer.contact.full.read','audit-2.2','ACTIVE',CURRENT_TIMESTAMP)
ON CONFLICT (role_key,permission_key) DO UPDATE
SET source_catalog_version='audit-2.2',
    status='ACTIVE';

-- Existing Tenant role bundles are materialized snapshots. Add this newly-approved
-- Executive-only capability to already-onboarded Executive bundles. Reuse a real
-- prior assignment actor from that Tenant where available; if a Tenant has an
-- Executive operating-role assignment but no bundle row, reuse that assignment's
-- actor. No synthetic USER is invented by the migration.
WITH candidate_actor AS (
    SELECT DISTINCT ON (tenant_id)
           tenant_id, assigned_by_user_id
    FROM (
        SELECT tenant_id, assigned_by_user_id, assigned_at_utc, 1 AS priority
        FROM security.tenant_role_permissions
        WHERE role_key='Executive'

        UNION ALL

        SELECT tenant_id, assigned_by_user_id, assigned_at_utc, 2 AS priority
        FROM security.user_tenant_operating_roles
        WHERE role_key='Executive'
    ) source
    WHERE assigned_by_user_id IS NOT NULL
    ORDER BY tenant_id, priority, assigned_at_utc
)
INSERT INTO security.tenant_role_permissions
(tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
SELECT tenant_id,
       'Executive',
       'audit.customer.contact.full.read',
       assigned_by_user_id,
       CURRENT_TIMESTAMP
FROM candidate_actor
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
