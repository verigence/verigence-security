-- Verigence Security v2 guarded legacy RBAC reconciliation.
-- IMPORTANT: Do not wire this migration into automatic DEV deployment until the
-- scripts/security_v2_reconciliation_report.sql output has been reviewed as clean.
-- This migration never chooses a winner for ambiguous legacy data.

BEGIN;

DO $$
DECLARE
  conflicts integer;
BEGIN
  -- One legacy direct operating role per USER/Tenant is required.
  SELECT count(*) INTO conflicts
  FROM (
    SELECT ura.user_id,ura.tenant_id
    FROM security.user_role_assignments ura
    JOIN security.roles r
      ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
    WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
      AND r.role_key IN ('PC','TL','PM','CRM','Executive')
    GROUP BY ura.user_id,ura.tenant_id
    HAVING count(*)>1
  ) q;
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % USER/Tenant pairs have multiple active legacy operating roles', conflicts;
  END IF;

  -- No assigned active custom role can be mapped automatically.
  SELECT count(*) INTO conflicts
  FROM security.user_role_assignments ura
  JOIN security.roles r
    ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
  WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
    AND r.role_key NOT IN ('PC','TL','PM','CRM','Executive');
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % active legacy USER role assignments use unmapped custom roles', conflicts;
  END IF;

  -- Group-derived extra roles cannot be silently promoted to direct v2 roles.
  SELECT count(*) INTO conflicts
  FROM (
    SELECT DISTINCT gm.user_id,gm.tenant_id,gra.role_id
    FROM security.group_memberships gm
    JOIN security.groups g
      ON g.tenant_id=gm.tenant_id AND g.group_id=gm.group_id AND g.status='ACTIVE'
    JOIN security.group_role_assignments gra
      ON gra.tenant_id=g.tenant_id AND gra.group_id=g.group_id AND gra.status='ACTIVE'
    WHERE gm.status='ACTIVE'
      AND NOT EXISTS (
        SELECT 1 FROM security.user_role_assignments ura
        WHERE ura.tenant_id=gm.tenant_id
          AND ura.user_id=gm.user_id
          AND ura.role_id=gra.role_id
          AND ura.status='ACTIVE'
      )
  ) q;
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % group-derived legacy roles are not direct assignments', conflicts;
  END IF;

  -- One PM candidate per Tenant.
  SELECT count(*) INTO conflicts
  FROM (
    SELECT ura.tenant_id
    FROM security.user_role_assignments ura
    JOIN security.roles r
      ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
    WHERE ura.status='ACTIVE' AND r.status='ACTIVE' AND r.role_key='PM'
    GROUP BY ura.tenant_id
    HAVING count(DISTINCT ura.user_id)>1
  ) q;
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % Tenants have multiple active legacy PM candidates', conflicts;
  END IF;

  -- Old platform admin personas have no approved automatic mapping except SuperAdmin.
  SELECT count(*) INTO conflicts
  FROM security.platform_user_role_assignments
  WHERE status='ACTIVE' AND role_key<>'platform.super_admin';
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % active legacy platform-admin assignments have no approved target mapping', conflicts;
  END IF;

  -- Target runtime does not create/use INVITED or EXITED states.
  SELECT count(*) INTO conflicts
  FROM security.users
  WHERE status NOT IN ('PENDING','REJECTED','ACTIVE','SUSPENDED','DISABLED');
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % USERs have legacy lifecycle states requiring explicit review', conflicts;
  END IF;

  -- Legacy operating assignments cannot coexist with v2 admin classification.
  SELECT count(*) INTO conflicts
  FROM security.user_role_assignments ura
  JOIN security.roles r
    ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
  JOIN security.user_admin_role_assignments a
    ON a.user_id=ura.user_id AND a.status='ACTIVE'
  WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
    AND r.role_key IN ('PC','TL','PM','CRM','Executive');
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % legacy operating assignments conflict with active v2 admin classifications', conflicts;
  END IF;

  -- If a USER/Tenant is already represented in v2, it must agree with legacy.
  SELECT count(*) INTO conflicts
  FROM security.user_role_assignments ura
  JOIN security.roles r
    ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
  JOIN security.user_tenant_operating_roles v2
    ON v2.user_id=ura.user_id AND v2.tenant_id=ura.tenant_id AND v2.status='ACTIVE'
  WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
    AND r.role_key IN ('PC','TL','PM','CRM','Executive')
    AND v2.role_key<>r.role_key;
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % existing v2 operating assignments disagree with legacy', conflicts;
  END IF;

  -- Every legacy permission being preserved must still be ACTIVE in the canonical catalogue.
  SELECT count(*) INTO conflicts
  FROM security.role_permissions rp
  JOIN security.roles r
    ON r.tenant_id=rp.tenant_id AND r.role_id=rp.role_id
  JOIN security.permissions p ON p.permission_key=rp.permission_key
  WHERE r.status='ACTIVE'
    AND r.role_key IN ('PC','TL','PM','CRM','Executive')
    AND p.status<>'ACTIVE';
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % legacy operating-role permission mappings reference non-ACTIVE permissions', conflicts;
  END IF;
END $$;

-- Existing v2 Tenant bundles must not be silently overwritten. For each Tenant/role that
-- already has v2 rows, compare against the expected legacy bundle (or platform default when
-- the Tenant never had that legacy role). Any set difference blocks the migration.
DO $$
DECLARE
  conflicts integer;
BEGIN
  WITH fixed_roles(role_key) AS (
    VALUES ('PC'),('TL'),('PM'),('CRM'),('Executive')
  ),
  legacy_roles AS (
    SELECT tenant_id,role_key,role_id
    FROM security.roles
    WHERE status='ACTIVE' AND role_key IN ('PC','TL','PM','CRM','Executive')
  ),
  expected AS (
    SELECT lr.tenant_id,lr.role_key,rp.permission_key
    FROM legacy_roles lr
    JOIN security.role_permissions rp
      ON rp.tenant_id=lr.tenant_id AND rp.role_id=lr.role_id
    UNION ALL
    SELECT t.tenant_id,fr.role_key,d.permission_key
    FROM security.tenants t
    CROSS JOIN fixed_roles fr
    JOIN security.platform_role_permission_defaults d
      ON d.role_key=fr.role_key AND d.status='ACTIVE'
    WHERE NOT EXISTS (
      SELECT 1 FROM legacy_roles lr
      WHERE lr.tenant_id=t.tenant_id AND lr.role_key=fr.role_key
    )
  ),
  existing_pairs AS (
    SELECT DISTINCT tenant_id,role_key
    FROM security.tenant_role_permissions
    WHERE role_key IN ('PC','TL','PM','CRM','Executive')
  ),
  diff AS (
    SELECT ep.tenant_id,ep.role_key
    FROM existing_pairs ep
    WHERE EXISTS (
      (SELECT permission_key FROM security.tenant_role_permissions
       WHERE tenant_id=ep.tenant_id AND role_key=ep.role_key)
      EXCEPT
      (SELECT permission_key FROM expected
       WHERE tenant_id=ep.tenant_id AND role_key=ep.role_key)
    )
    OR EXISTS (
      (SELECT permission_key FROM expected
       WHERE tenant_id=ep.tenant_id AND role_key=ep.role_key)
      EXCEPT
      (SELECT permission_key FROM security.tenant_role_permissions
       WHERE tenant_id=ep.tenant_id AND role_key=ep.role_key)
    )
  )
  SELECT count(*) INTO conflicts FROM diff;
  IF conflicts>0 THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: % existing Tenant role bundles disagree with legacy/default expected bundles', conflicts;
  END IF;
END $$;

DO $$
DECLARE super_admin_user uuid;
BEGIN
  SELECT user_id INTO super_admin_user
  FROM security.user_admin_role_assignments
  WHERE role_key='SuperAdmin' AND scope_type='PLATFORM' AND status='ACTIVE'
  LIMIT 1;
  IF super_admin_user IS NULL THEN
    RAISE EXCEPTION 'V2 reconciliation blocked: canonical active SuperAdmin is required';
  END IF;

  -- Seed missing Tenant bundles. Existing legacy known-role permission mappings win;
  -- platform defaults are used only when that Tenant had no legacy role object.
  WITH fixed_roles(role_key) AS (
    VALUES ('PC'),('TL'),('PM'),('CRM'),('Executive')
  ),
  legacy_roles AS (
    SELECT tenant_id,role_key,role_id
    FROM security.roles
    WHERE status='ACTIVE' AND role_key IN ('PC','TL','PM','CRM','Executive')
  ),
  expected AS (
    SELECT lr.tenant_id,lr.role_key,rp.permission_key
    FROM legacy_roles lr
    JOIN security.role_permissions rp
      ON rp.tenant_id=lr.tenant_id AND rp.role_id=lr.role_id
    UNION ALL
    SELECT t.tenant_id,fr.role_key,d.permission_key
    FROM security.tenants t
    CROSS JOIN fixed_roles fr
    JOIN security.platform_role_permission_defaults d
      ON d.role_key=fr.role_key AND d.status='ACTIVE'
    WHERE NOT EXISTS (
      SELECT 1 FROM legacy_roles lr
      WHERE lr.tenant_id=t.tenant_id AND lr.role_key=fr.role_key
    )
  )
  INSERT INTO security.tenant_role_permissions
  (tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
  SELECT e.tenant_id,e.role_key,e.permission_key,super_admin_user,CURRENT_TIMESTAMP
  FROM expected e
  WHERE NOT EXISTS (
    SELECT 1 FROM security.tenant_role_permissions trp
    WHERE trp.tenant_id=e.tenant_id AND trp.role_key=e.role_key
  )
  ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;
END $$;

-- Copy clean direct fixed-role assignments. Reusing the legacy assignment UUID is safe because
-- the legacy and v2 assignment tables have independent primary-key namespaces.
INSERT INTO security.user_tenant_operating_roles
(assignment_id,user_id,tenant_id,role_key,status,valid_from_utc,valid_to_utc,
 assigned_by_user_id,assigned_at_utc,ended_at_utc)
SELECT ura.assignment_id,ura.user_id,ura.tenant_id,r.role_key,'ACTIVE',
       ura.valid_from_utc,ura.valid_to_utc,ura.assigned_by_user_id,ura.assigned_at_utc,NULL
FROM security.user_role_assignments ura
JOIN security.roles r
  ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
JOIN security.users u ON u.user_id=ura.user_id AND u.status='ACTIVE'
JOIN security.tenants t ON t.tenant_id=ura.tenant_id AND t.status='ACTIVE'
WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
  AND r.role_key IN ('PC','TL','PM','CRM','Executive')
  AND NOT EXISTS (
    SELECT 1 FROM security.user_tenant_operating_roles v2
    WHERE v2.user_id=ura.user_id AND v2.tenant_id=ura.tenant_id AND v2.status='ACTIVE'
  );

COMMIT;
