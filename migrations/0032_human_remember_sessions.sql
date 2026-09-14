-- Standards-aligned persistent human sign-in credential store.
-- The client receives only an opaque random token; Security stores only SHA-256 hashes.
-- Access tokens remain short-lived and unchanged. The remember credential is used only by
-- /security/v1/auth/resume and is rotated after every successful resume.

CREATE TABLE security.human_remember_sessions (
  access_session_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  device_id uuid NOT NULL,
  token_hash char(64) NOT NULL,
  previous_token_hash char(64),
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','REVOKED','EXPIRED')),
  created_at_utc timestamptz NOT NULL,
  expires_at_utc timestamptz NOT NULL,
  last_used_at_utc timestamptz NOT NULL,
  revoked_at_utc timestamptz,
  CHECK (expires_at_utc > created_at_utc)
);

CREATE UNIQUE INDEX uq_human_remember_current_token_hash
ON security.human_remember_sessions(token_hash);

CREATE INDEX ix_human_remember_previous_token_hash
ON security.human_remember_sessions(previous_token_hash)
WHERE previous_token_hash IS NOT NULL;

CREATE UNIQUE INDEX uq_active_human_remember_session
ON security.human_remember_sessions(user_id)
WHERE status='ACTIVE';

CREATE INDEX ix_human_remember_user_status
ON security.human_remember_sessions(user_id, status, created_at_utc DESC);
