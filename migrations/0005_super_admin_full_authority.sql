-- Verigence Security — Platform Super Admin full-authority invariant
-- Clarifies the v1.4.2 bootstrap model: one built-in platform.super_admin role
-- is sufficient to initialize and administer the entire Security platform.

BEGIN;

-- Backfill every currently ACTIVE Security permission to the built-in Super Admin role.
INSERT INTO security.platform_role_permissions
(role_key,permission_key,assigned_at_utc)
SELECT 'platform.super_admin', p.permission_key, CURRENT_TIMESTAMP
FROM security.permissions p
WHERE p.status='ACTIVE'
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- Remove stale Super Admin grants when a permission is no longer ACTIVE.
DELETE FROM security.platform_role_permissions prp
USING security.permissions p
WHERE prp.role_key='platform.super_admin'
  AND prp.permission_key=p.permission_key
  AND p.status<>'ACTIVE';

-- Keep the invariant true automatically as the permission catalogue evolves.
CREATE OR REPLACE FUNCTION security.sync_platform_super_admin_permission()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.status='ACTIVE' THEN
    INSERT INTO security.platform_role_permissions
    (role_key,permission_key,assigned_at_utc)
    VALUES ('platform.super_admin',NEW.permission_key,CURRENT_TIMESTAMP)
    ON CONFLICT (role_key,permission_key) DO NOTHING;
  ELSE
    DELETE FROM security.platform_role_permissions
    WHERE role_key='platform.super_admin'
      AND permission_key=NEW.permission_key;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_sync_platform_super_admin_permission
ON security.permissions;

CREATE TRIGGER trg_sync_platform_super_admin_permission
AFTER INSERT OR UPDATE OF status ON security.permissions
FOR EACH ROW
EXECUTE FUNCTION security.sync_platform_super_admin_permission();

COMMIT;
