-- Verigence Security v2 — global Attendance HRADMIN assignment
-- Additive only. The tenant-scoped 0027 table is preserved unchanged for rollback compatibility.

BEGIN;

-- A global role cannot safely collapse multiple ACTIVE Tenant-scoped HRADMIN rows for one USER.
-- Refuse the migration instead of selecting a Tenant or assignment implicitly.
DO $$
DECLARE
  ambiguous_users integer;
BEGIN
  SELECT count(*) INTO ambiguous_users
  FROM (
    SELECT user_id
    FROM security.user_module_role_assignments
    WHERE module_key='attendance'
      AND role_key='HRADMIN'
      AND status='ACTIVE'
    GROUP BY user_id
    HAVING count(*) > 1
  ) conflicts;

  IF ambiguous_users > 0 THEN
    RAISE EXCEPTION
      'Global Attendance HRADMIN migration blocked: % USER(s) have multiple ACTIVE Tenant-scoped HRADMIN assignments',
      ambiguous_users;
  END IF;
END $$;

-- Generic global module-role assignments. This table is intentionally not Tenant-scoped.
-- It can support future truly global module roles without changing operating-role cardinality.
CREATE TABLE IF NOT EXISTS security.user_global_module_role_assignments (
    assignment_id       uuid PRIMARY KEY,
    user_id             uuid NOT NULL REFERENCES security.users(user_id),
    module_key          varchar(80) NOT NULL,
    role_key            varchar(80) NOT NULL,
    status              varchar(20) NOT NULL CHECK (status IN ('ACTIVE','ENDED')),
    valid_from_utc      timestamptz,
    valid_to_utc        timestamptz,
    assigned_by_user_id uuid NOT NULL REFERENCES security.users(user_id),
    assigned_at_utc     timestamptz NOT NULL,
    ended_at_utc        timestamptz,
    FOREIGN KEY (module_key,role_key)
      REFERENCES security.module_roles(module_key,role_key),
    CHECK (valid_to_utc IS NULL OR valid_from_utc IS NULL OR valid_to_utc>valid_from_utc)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_user_global_module_role
ON security.user_global_module_role_assignments(user_id,module_key,role_key)
WHERE status='ACTIVE';

CREATE INDEX IF NOT EXISTS ix_user_global_module_roles_runtime
ON security.user_global_module_role_assignments(user_id,module_key,status);

-- Preserve any existing unambiguous ACTIVE HRADMIN assignment when switching the
-- authorization resolver to the global table. The legacy row remains untouched so
-- reverting the application to the pre-0028 behavior does not require a data rollback.
INSERT INTO security.user_global_module_role_assignments (
    assignment_id,user_id,module_key,role_key,status,valid_from_utc,valid_to_utc,
    assigned_by_user_id,assigned_at_utc,ended_at_utc
)
SELECT
    assignment_id,user_id,module_key,role_key,status,valid_from_utc,valid_to_utc,
    assigned_by_user_id,assigned_at_utc,ended_at_utc
FROM security.user_module_role_assignments
WHERE module_key='attendance'
  AND role_key='HRADMIN'
  AND status='ACTIVE'
ON CONFLICT DO NOTHING;

COMMIT;
