-- Verigence Security — SevaSutra (workshop audit) module and the ANALYST operating role
--
-- SevaSutra audits a dealership's workshop (after-sales service): gate registers, ROs, pre-invoices,
-- final invoices, gate passes, payments, warranty, insurance. It signs people in through Security and
-- asks Security, per Project, what each person may do -- the same boundary Audit Core uses.
--
-- Three operating roles run it (product owner, 6 Nov 2026; docs/SEVASUTRA_MODULE_RBAC_2026-11-06.md):
--   ANALYST  new. On site at one outlet: captures the evidence, audits it, raises observations.
--   TL       existing. Approves observations before they reach the Dealer Principal, issues the
--            daily report, verifies leakage.
--   PM       existing. Owns thresholds, the labour benchmark and recurring schedules; settles leakage.
-- TL and PM are the existing Verigence roles: SevaSutra permissions are added to their bundles, so a
-- person needs no second role key. Outlet scope stays in SevaSutra, as it stays in Audit Core.
--
-- Additive and idempotent, in the shape of 0033 (module permissions) and 0046 (operating role).

BEGIN;

-- 1. The SevaSutra permission catalogue. Registering permissions under module_key 'sevasutra' also
--    makes 'sevasutra' a registered audience for service tokens.
WITH sevasutra_permissions(permission_key,resource_key,action_key) AS (
  VALUES
    ('sevasutra.project.read','project','read'),
    ('sevasutra.evidence.upload','evidence','upload'),
    ('sevasutra.evidence.verify','evidence','verify'),
    ('sevasutra.observation.raise','observation','raise'),
    ('sevasutra.observation.approve','observation','approve'),
    ('sevasutra.report.issue','report','issue'),
    ('sevasutra.leakage.verify','leakage','verify'),
    ('sevasutra.leakage.settle','leakage','settle'),
    ('sevasutra.risk.close','risk','close'),
    ('sevasutra.benchmark.propose','benchmark','propose'),
    ('sevasutra.benchmark.approve','benchmark','approve'),
    ('sevasutra.task.assign','task','assign'),
    ('sevasutra.task.schedule','task','schedule'),
    ('sevasutra.settings.manage','settings','manage'),
    ('sevasutra.team.manage','team','manage'),
    ('sevasutra.analytics.read','analytics','read')
)
INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,display_name,catalog_version,updated_at_utc)
SELECT permission_key,'sevasutra',resource_key,action_key,NULL,'ACTIVE',permission_key,
       'sevasutra-1.0',CURRENT_TIMESTAMP
FROM sevasutra_permissions
ON CONFLICT (permission_key) DO UPDATE
SET module_key='sevasutra',
    resource_key=EXCLUDED.resource_key,
    action_key=EXCLUDED.action_key,
    status='ACTIVE',
    catalog_version='sevasutra-1.0',
    updated_at_utc=CURRENT_TIMESTAMP;

-- 2. ANALYST as an OPERATING role. user_tenant_operating_roles.role_key and
--    platform_role_permission_defaults.role_key both reference role_definitions.
INSERT INTO security.role_definitions
(role_key,role_class,display_name,status,created_at_utc,updated_at_utc)
VALUES
  ('ANALYST','OPERATING','Analyst','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
ON CONFLICT (role_key) DO NOTHING;

-- 3. The CHECK listing assignable operating-role keys, replaced under its existing name (as in 0046).
ALTER TABLE security.user_tenant_operating_roles
  DROP CONSTRAINT IF EXISTS user_tenant_operating_roles_role_key_check;

ALTER TABLE security.user_tenant_operating_roles
  ADD CONSTRAINT user_tenant_operating_roles_role_key_check
  CHECK (role_key IN ('PC','TL','PM','CRM','Executive','REVIEWER','ANALYST'));

-- 4. Platform default bundles. The Analyst detects and documents; the Team Lead approves and reports;
--    the PM governs and settles. Whoever raised an observation never approves it: the Analyst holds
--    no approve permission at all.
WITH role_bundle(role_key,permission_keys) AS (
  VALUES
  ('ANALYST',ARRAY[
    'sevasutra.project.read',
    'sevasutra.evidence.upload',
    'sevasutra.evidence.verify',
    'sevasutra.observation.raise',
    'sevasutra.benchmark.propose',
    'sevasutra.analytics.read'
  ]::varchar[]),
  ('TL',ARRAY[
    'sevasutra.project.read',
    'sevasutra.evidence.upload',
    'sevasutra.evidence.verify',
    'sevasutra.observation.raise',
    'sevasutra.observation.approve',
    'sevasutra.report.issue',
    'sevasutra.leakage.verify',
    'sevasutra.risk.close',
    'sevasutra.task.assign',
    'sevasutra.analytics.read'
  ]::varchar[]),
  ('PM',ARRAY[
    'sevasutra.project.read',
    'sevasutra.observation.approve',
    'sevasutra.report.issue',
    'sevasutra.leakage.verify',
    'sevasutra.leakage.settle',
    'sevasutra.risk.close',
    'sevasutra.benchmark.approve',
    'sevasutra.task.assign',
    'sevasutra.task.schedule',
    'sevasutra.settings.manage',
    'sevasutra.team.manage',
    'sevasutra.analytics.read'
  ]::varchar[])
),
approved_defaults AS (
  SELECT role_key,unnest(permission_keys) AS permission_key
  FROM role_bundle
)
INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT role_key,permission_key,'sevasutra-1.0','ACTIVE',CURRENT_TIMESTAMP
FROM approved_defaults
ON CONFLICT (role_key,permission_key) DO NOTHING;

-- 5. Projects provisioned before this migration hold their own copy of the bundles and nothing
--    re-seeds them, so the SevaSutra permissions are backfilled for ANALYST, TL and PM. The assigning
--    actor is carried from each tenant's existing rows (as in 0046). Audit Core ignores sevasutra.*
--    keys, so a sales-audit Project is unaffected.
INSERT INTO security.tenant_role_permissions
(tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
SELECT existing.tenant_id,
       d.role_key,
       d.permission_key,
       existing.assigned_by_user_id,
       CURRENT_TIMESTAMP
FROM security.platform_role_permission_defaults d
JOIN security.permissions p
  ON p.permission_key=d.permission_key
 AND p.status='ACTIVE'
JOIN (
  SELECT DISTINCT ON (tenant_id) tenant_id,assigned_by_user_id
  FROM security.tenant_role_permissions
  ORDER BY tenant_id,assigned_at_utc
) AS existing ON true
WHERE d.status='ACTIVE'
  AND d.role_key IN ('ANALYST','TL','PM')
  AND d.permission_key LIKE 'sevasutra.%'
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
