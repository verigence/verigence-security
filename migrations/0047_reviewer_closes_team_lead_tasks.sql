-- Verigence Security — a Reviewer closes the Team Lead's tasks of their outlets
--
-- Product owner, 2026-11-02: "The tasks marked for TL closure should now also be
-- marked for Reviewers for the given outlets." One task, not a copy: Audit Core
-- puts a task assigned to the TL role on the queue of every Reviewer whose
-- assignment covers the task's outlet, and either of them closes it
-- (audit_core.task_closure_roles). Which tasks and which outlets is Audit
-- Core's decision; what this migration carries is the capability, on the
-- token: the Task Queue read and the task action, which 0046 withheld.
--
--   audit.work.read    the Task Queue (Journey tasks and Task Manager tasks)
--   audit.work.update  act on a task: comment, complete, accept an exception,
--                      give the verdict on a finding
--
-- Still withheld: audit.work.manage (reassigning and cancelling others' work),
-- every *.verify, audit.finding.create, audit.review.decide and any upload.
--
-- Additive and idempotent, in the shape of 0046: the platform default bundle
-- for new Projects, then the same two permissions on every existing Project
-- that already carries the REVIEWER bundle (nothing re-seeds an existing one).

BEGIN;

DO $$
DECLARE missing_count integer;
BEGIN
  SELECT count(*) INTO missing_count
  FROM unnest(ARRAY['audit.work.read','audit.work.update']::varchar[]) AS r(permission_key)
  LEFT JOIN security.permissions p ON p.permission_key=r.permission_key
  WHERE p.permission_key IS NULL OR p.status <> 'ACTIVE';

  IF missing_count <> 0 THEN
    RAISE EXCEPTION 'REVIEWER task permissions reference % missing/non-ACTIVE permission(s)', missing_count;
  END IF;
END $$;

INSERT INTO security.platform_role_permission_defaults
(role_key,permission_key,source_catalog_version,status,created_at_utc)
SELECT 'REVIEWER',permission_key,'audit-2.1','ACTIVE',CURRENT_TIMESTAMP
FROM unnest(ARRAY['audit.work.read','audit.work.update']::varchar[]) AS r(permission_key)
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
CROSS JOIN unnest(ARRAY['audit.work.read','audit.work.update']::varchar[]) AS r(permission_key)
ON CONFLICT (tenant_id,role_key,permission_key) DO NOTHING;

COMMIT;
