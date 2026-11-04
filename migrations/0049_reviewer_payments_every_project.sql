-- Verigence Security — a Reviewer reads and records payments in every Project
--
-- Product owner, 2026-11-04 ("payments in all Projects"). On 2026-10-30 the
-- Reviewer was given payment access (read and write) on Mahindra Orissa only,
-- as a grant on that one Project. It now belongs to the Reviewer's default
-- bundle, so every Project has it, including Projects created later.
--
--   audit.payment.read    see the receipts and payment checks on a deal
--   audit.payment.write   add or correct a receipt
--
-- Still withheld: audit.payment.verify (the Team Lead's sign-off).
--
-- Additive and idempotent, in the shape of 0047: the platform default bundle
-- for new Projects, then the same two permissions on every existing Project
-- that already carries the REVIEWER bundle (nothing re-seeds an existing one).
-- Mahindra Orissa already holds both, which ON CONFLICT leaves as they are.

BEGIN;

DO $$
DECLARE missing_count integer;
BEGIN
  SELECT count(*) INTO missing_count
  FROM unnest(ARRAY['audit.payment.read','audit.payment.write']::varchar[]) AS r(permission_key)
  LEFT JOIN security.permissions p ON p.permission_key=r.permission_key
  WHERE p.permission_key IS NULL OR p.status <> 'ACTIVE';

  IF missing_count <> 0 THEN
    RAISE EXCEPTION 'REVIEWER payment permissions reference % missing/non-ACTIVE permission(s)', missing_count;
  END IF;
END $$;

INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT 'REVIEWER',permission_key,'audit-2.1','ACTIVE',CURRENT_TIMESTAMP
FROM unnest(ARRAY['audit.payment.read','audit.payment.write']::varchar[]) AS r(permission_key)
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- Every Project that already has the Reviewer bundle, attributed to whoever
-- granted that Project's Reviewer bundle.
INSERT INTO security.tenant_role_permissions
(tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
SELECT existing.tenant_id,'REVIEWER',r.permission_key,existing.assigned_by_user_id,CURRENT_TIMESTAMP
FROM (
  SELECT DISTINCT ON (tenant_id) tenant_id,assigned_by_user_id
  FROM security.tenant_role_permissions
  WHERE role_key='REVIEWER'
  ORDER BY tenant_id,assigned_at_utc
) AS existing
CROSS JOIN unnest(ARRAY['audit.payment.read','audit.payment.write']::varchar[]) AS r(permission_key)
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
