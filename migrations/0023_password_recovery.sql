-- Verigence Security — backend-only password recovery
--
-- Password reset codes and new passwords remain transient request secrets. Security persists only
-- attempt/provider identifiers and lifecycle timestamps so Web/Mobile never need direct Clerk access.

BEGIN;

CREATE TABLE IF NOT EXISTS security.password_reset_attempts (
  password_reset_attempt_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  clerk_user_id varchar(240) NOT NULL,
  clerk_email_address_id varchar(240) NOT NULL,
  clerk_email_verification_id varchar(240) NOT NULL,
  status varchar(24) NOT NULL CHECK (status IN ('PENDING','COMPLETED','EXPIRED','CANCELLED')),
  submitted_source_ip inet,
  correlation_id varchar(200),
  created_at_utc timestamptz NOT NULL,
  expires_at_utc timestamptz NOT NULL,
  completed_at_utc timestamptz
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_password_reset_pending_user
ON security.password_reset_attempts (user_id)
WHERE status='PENDING';

CREATE INDEX IF NOT EXISTS ix_password_reset_attempt_expiry
ON security.password_reset_attempts (expires_at_utc)
WHERE status='PENDING';

COMMIT;
