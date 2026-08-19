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

COMMIT;
