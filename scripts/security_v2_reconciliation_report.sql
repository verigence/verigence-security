-- Verigence Security v2 mandatory pre-cutover reconciliation report.
-- READ ONLY. This script never mutates data and never selects a winner for ambiguity.
-- Run against the actual DEV database after migrations 0011-0015 are present.

\echo '=== 1. USERS WITH MULTIPLE ACTIVE DIRECT LEGACY ROLES IN ONE TENANT ==='
SELECT ura.user_id,ura.tenant_id,
       count(*) AS active_role_count,
       array_agg(r.role_key ORDER BY r.role_key) AS role_keys
FROM security.user_role_assignments ura
JOIN security.roles r
  ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
GROUP BY ura.user_id,ura.tenant_id
HAVING count(*)>1
ORDER BY ura.tenant_id,ura.user_id;

\echo '=== 2. GROUP-DERIVED ACTIVE LEGACY ROLES NOT ALSO DIRECTLY ASSIGNED ==='
SELECT DISTINCT gm.user_id,gm.tenant_id,r.role_key,g.group_key,g.group_id
FROM security.group_memberships gm
JOIN security.groups g
  ON g.tenant_id=gm.tenant_id AND g.group_id=gm.group_id AND g.status='ACTIVE'
JOIN security.group_role_assignments gra
  ON gra.tenant_id=g.tenant_id AND gra.group_id=g.group_id AND gra.status='ACTIVE'
JOIN security.roles r
  ON r.tenant_id=gra.tenant_id AND r.role_id=gra.role_id AND r.status='ACTIVE'
WHERE gm.status='ACTIVE'
  AND NOT EXISTS (
    SELECT 1
    FROM security.user_role_assignments ura
    WHERE ura.tenant_id=gm.tenant_id
      AND ura.user_id=gm.user_id
      AND ura.role_id=gra.role_id
      AND ura.status='ACTIVE'
  )
ORDER BY gm.tenant_id,gm.user_id,r.role_key;

\echo '=== 3. ADMIN + OPERATING MIXTURES (V2) ==='
SELECT DISTINCT a.user_id,
       array_agg(DISTINCT a.role_key ORDER BY a.role_key) AS admin_roles,
       array_agg(DISTINCT o.role_key ORDER BY o.role_key) AS operating_roles
FROM security.user_admin_role_assignments a
JOIN security.user_tenant_operating_roles o
  ON o.user_id=a.user_id AND o.status='ACTIVE'
WHERE a.status='ACTIVE'
GROUP BY a.user_id
ORDER BY a.user_id;

\echo '=== 4. LEGACY PLATFORM ADMIN + LEGACY/NEW OPERATING MIXTURES ==='
WITH legacy_admin AS (
  SELECT DISTINCT pura.user_id,pura.role_key
  FROM security.platform_user_role_assignments pura
  WHERE pura.status='ACTIVE'
), operating AS (
  SELECT ura.user_id,ura.tenant_id,r.role_key
  FROM security.user_role_assignments ura
  JOIN security.roles r
    ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
  WHERE ura.status='ACTIVE' AND r.status='ACTIVE'
  UNION ALL
  SELECT user_id,tenant_id,role_key
  FROM security.user_tenant_operating_roles
  WHERE status='ACTIVE'
)
SELECT la.user_id,
       array_agg(DISTINCT la.role_key ORDER BY la.role_key) AS legacy_admin_roles,
       array_agg(DISTINCT op.role_key ORDER BY op.role_key) AS operating_roles
FROM legacy_admin la
JOIN operating op ON op.user_id=la.user_id
GROUP BY la.user_id
ORDER BY la.user_id;

\echo '=== 5. TENANTS WITH MORE THAN ONE LEGACY PM CANDIDATE ==='
SELECT ura.tenant_id,count(DISTINCT ura.user_id) AS pm_candidates,
       array_agg(DISTINCT ura.user_id ORDER BY ura.user_id) AS user_ids
FROM security.user_role_assignments ura
JOIN security.roles r
  ON r.tenant_id=ura.tenant_id AND r.role_id=ura.role_id
WHERE ura.status='ACTIVE' AND r.status='ACTIVE' AND lower(r.role_key)='pm'
GROUP BY ura.tenant_id
HAVING count(DISTINCT ura.user_id)>1
ORDER BY ura.tenant_id;

\echo '=== 6. CUSTOM/UNMAPPABLE ACTIVE LEGACY TENANT ROLES ==='
SELECT r.tenant_id,r.role_id,r.role_key,r.role_name
FROM security.roles r
WHERE r.status='ACTIVE'
  AND r.role_key NOT IN ('PC','TL','PM','CRM','Executive')
ORDER BY r.tenant_id,r.role_key;

\echo '=== 7. PERMISSIONS AVAILABLE ONLY THROUGH ACTIVE GROUP->ROLE CHAINS ==='
WITH direct_permissions AS (
  SELECT DISTINCT ura.user_id,ura.tenant_id,rp.permission_key
  FROM security.user_role_assignments ura
  JOIN security.role_permissions rp
    ON rp.tenant_id=ura.tenant_id AND rp.role_id=ura.role_id
  WHERE ura.status='ACTIVE'
), group_permissions AS (
  SELECT DISTINCT gm.user_id,gm.tenant_id,rp.permission_key,g.group_key
  FROM security.group_memberships gm
  JOIN security.groups g
    ON g.tenant_id=gm.tenant_id AND g.group_id=gm.group_id AND g.status='ACTIVE'
  JOIN security.group_role_assignments gra
    ON gra.tenant_id=g.tenant_id AND gra.group_id=g.group_id AND gra.status='ACTIVE'
  JOIN security.role_permissions rp
    ON rp.tenant_id=gra.tenant_id AND rp.role_id=gra.role_id
  WHERE gm.status='ACTIVE'
)
SELECT gp.user_id,gp.tenant_id,gp.permission_key,
       array_agg(DISTINCT gp.group_key ORDER BY gp.group_key) AS source_groups
FROM group_permissions gp
LEFT JOIN direct_permissions dp
  ON dp.user_id=gp.user_id
 AND dp.tenant_id=gp.tenant_id
 AND dp.permission_key=gp.permission_key
WHERE dp.permission_key IS NULL
GROUP BY gp.user_id,gp.tenant_id,gp.permission_key
ORDER BY gp.tenant_id,gp.user_id,gp.permission_key;

\echo '=== 8. ARBITRARY ACTIVE GROUPS NOT EQUIVALENT TO ROLE-ALIGNED GROUPS ==='
SELECT tenant_id,group_id,group_key,group_name
FROM security.groups
WHERE status='ACTIVE'
  AND group_key NOT IN ('PC','TL','PM','CRM','Executive')
ORDER BY tenant_id,group_key;

\echo '=== 9. LEGACY USER STATES REQUIRING EXPLICIT RECONCILIATION ==='
SELECT status,count(*) AS user_count,array_agg(user_id ORDER BY user_id) AS user_ids
FROM security.users
WHERE status NOT IN ('PENDING','REJECTED','ACTIVE','SUSPENDED','DISABLED')
GROUP BY status
ORDER BY status;

\echo '=== 10. SUPERADMIN ASSIGNMENTS (EXPECT EXACTLY ONE APPROVED V2 IDENTITY) ==='
SELECT 'v2' AS source,a.user_id,a.role_key,a.scope_type,a.scope_id,a.status
FROM security.user_admin_role_assignments a
WHERE a.role_key='SuperAdmin' AND a.status='ACTIVE'
UNION ALL
SELECT 'legacy' AS source,pura.user_id,pura.role_key,'PLATFORM',NULL,pura.status
FROM security.platform_user_role_assignments pura
WHERE pura.role_key='platform.super_admin' AND pura.status='ACTIVE'
ORDER BY source,user_id;

\echo '=== 11. SERVICEINTEGRATION PRINCIPALS STILL CARRYING LEGACY TENANT SCOPES ==='
SELECT si.integration_key,pts.principal_id,pts.tenant_id,pts.status
FROM security.service_integrations si
JOIN security.principal_tenant_scopes pts ON pts.principal_id=si.principal_id
WHERE pts.status='ACTIVE'
ORDER BY si.integration_key,pts.tenant_id;

\echo '=== 12. SERVICEINTEGRATION PRINCIPALS STILL CARRYING LEGACY PERMISSION GRANTS ==='
SELECT si.integration_key,ppg.principal_id,ppg.tenant_id,ppg.permission_key,ppg.status
FROM security.service_integrations si
JOIN security.principal_permission_grants ppg ON ppg.principal_id=si.principal_id
WHERE ppg.status='ACTIVE'
ORDER BY si.integration_key,ppg.tenant_id,ppg.permission_key;

\echo '=== 13. V2 OPERATING ROLE COUNTS / PM SANITY ==='
SELECT tenant_id,role_key,count(*) AS active_assignments
FROM security.user_tenant_operating_roles
WHERE status='ACTIVE'
GROUP BY tenant_id,role_key
ORDER BY tenant_id,role_key;

\echo '=== END: ANY NON-EMPTY AMBIGUITY SECTION MUST BE REVIEWED MANUALLY BEFORE DATA MIGRATION ==='
