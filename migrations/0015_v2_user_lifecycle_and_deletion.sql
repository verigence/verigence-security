-- Verigence Security v2 Phase-1 USER lifecycle and hard-deletion foundation.
-- Additive migration: retain legacy readable USER states while enabling REJECTED and
-- the approved global deletion-request/tombstone model.

BEGIN;

ALTER TABLE security.users
  DROP CONSTRAINT IF EXISTS users_status_check;
ALTER TABLE security.users
  ADD CONSTRAINT users_status_check
  CHECK (status IN (
    'PENDING','REJECTED','ACTIVE','SUSPENDED','DISABLED',
    'INVITED','EXITED'
  ));

CREATE TABLE IF NOT EXISTS security.user_deletion_requests (
  deletion_request_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES security.users(user_id) ON DELETE CASCADE,
  requested_by_user_id uuid REFERENCES security.users(user_id) ON DELETE SET NULL,
  requested_at_utc timestamptz NOT NULL,
  reason text,
  status varchar(20) NOT NULL
    CHECK (status IN ('REQUESTED','CANCELLED','COMPLETED','FAILED')),
  checked_by_user_id uuid REFERENCES security.users(user_id) ON DELETE SET NULL,
  checked_at_utc timestamptz,
  outcome text,
  correlation_id varchar(128) NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_open_user_deletion_request
ON security.user_deletion_requests(user_id)
WHERE status='REQUESTED';

CREATE INDEX IF NOT EXISTS ix_user_deletion_request_status_time
ON security.user_deletion_requests(status,requested_at_utc);

CREATE TABLE IF NOT EXISTS security.deleted_user_tombstones (
  tombstone_id uuid PRIMARY KEY,
  deleted_user_id uuid NOT NULL,
  deletion_request_id uuid NOT NULL,
  safe_actor_reference jsonb NOT NULL,
  deleted_at_utc timestamptz NOT NULL,
  retain_until_utc timestamptz NOT NULL,
  deletion_correlation_id varchar(128) NOT NULL,
  CHECK (retain_until_utc = deleted_at_utc + interval '21 days')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_deleted_user_tombstone_request
ON security.deleted_user_tombstones(deletion_request_id);

CREATE INDEX IF NOT EXISTS ix_deleted_user_tombstone_retention
ON security.deleted_user_tombstones(retain_until_utc);

-- Hard deletion must not erase or rewrite the historical identity of the USER who
-- previously performed an administrative/configuration action. For single-column FKs
-- to security.users, subject/object references become ON DELETE CASCADE, while actor
-- references (*_by_user_id / actor_user_id) deliberately retain the UUID without a live
-- USER FK. Application write services continue to validate the acting USER before writes.
DO $$
DECLARE
  fk record;
BEGIN
  FOR fk IN
    SELECT ns.nspname AS schema_name,
           tbl.relname AS table_name,
           con.conname AS constraint_name,
           att.attname AS column_name
    FROM pg_constraint con
    JOIN pg_class tbl ON tbl.oid=con.conrelid
    JOIN pg_namespace ns ON ns.oid=tbl.relnamespace
    JOIN pg_attribute att
      ON att.attrelid=con.conrelid
     AND att.attnum=con.conkey[1]
    WHERE con.contype='f'
      AND con.confrelid='security.users'::regclass
      AND array_length(con.conkey,1)=1
      AND array_length(con.confkey,1)=1
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.%I DROP CONSTRAINT %I',
      fk.schema_name,fk.table_name,fk.constraint_name
    );

    IF fk.column_name NOT LIKE '%\_by\_user\_id' ESCAPE '\'
       AND fk.column_name <> 'actor_user_id' THEN
      EXECUTE format(
        'ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY (%I) '
        'REFERENCES security.users(user_id) ON DELETE CASCADE',
        fk.schema_name,fk.table_name,fk.constraint_name,fk.column_name
      );
    END IF;
  END LOOP;
END $$;

-- Security events are retained historical evidence. Keep their principal UUID after a
-- live USER/principal is hard-deleted rather than requiring that principal row forever.
DO $$
DECLARE
  fk record;
BEGIN
  FOR fk IN
    SELECT ns.nspname AS schema_name,
           tbl.relname AS table_name,
           con.conname AS constraint_name
    FROM pg_constraint con
    JOIN pg_class tbl ON tbl.oid=con.conrelid
    JOIN pg_namespace ns ON ns.oid=tbl.relnamespace
    JOIN pg_attribute att
      ON att.attrelid=con.conrelid
     AND att.attnum=con.conkey[1]
    WHERE con.contype='f'
      AND con.confrelid='security.security_principals'::regclass
      AND ns.nspname='security'
      AND tbl.relname='security_events'
      AND att.attname='principal_id'
      AND array_length(con.conkey,1)=1
  LOOP
    EXECUTE format(
      'ALTER TABLE %I.%I DROP CONSTRAINT %I',
      fk.schema_name,fk.table_name,fk.constraint_name
    );
  END LOOP;
END $$;

COMMIT;
