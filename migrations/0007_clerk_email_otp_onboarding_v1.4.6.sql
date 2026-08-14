-- Verigence Security — Clerk-owned email OTP onboarding v1.4.6
-- Adds a short-lived pre-authorization workflow before Clerk client-side sign-up.
-- No Security USER is created until Clerk email verification has completed.

BEGIN;

CREATE TABLE IF NOT EXISTS security.platform_user_signup_attempts (
  signup_attempt_id uuid PRIMARY KEY,
  first_name varchar(120) NOT NULL,
  last_name varchar(120) NOT NULL,
  email varchar(320) NOT NULL,
  mobile varchar(20) NOT NULL,
  status varchar(40) NOT NULL CHECK (
    status IN ('AUTHORIZED_FOR_CLERK','COMPLETED','EXPIRED','CANCELLED')
  ),
  submitted_source_ip inet NOT NULL,
  correlation_id varchar(128) NOT NULL,
  created_at_utc timestamptz NOT NULL,
  expires_at_utc timestamptz NOT NULL,
  clerk_user_id varchar(240),
  completed_at_utc timestamptz,
  CHECK (expires_at_utc > created_at_utc),
  CHECK (
    (status='COMPLETED' AND clerk_user_id IS NOT NULL AND completed_at_utc IS NOT NULL)
    OR
    (status<>'COMPLETED' AND completed_at_utc IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS ix_platform_user_signup_attempt_status_expiry
ON security.platform_user_signup_attempts(status,expires_at_utc);

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_user_signup_attempt_email_live
ON security.platform_user_signup_attempts ((lower(email)))
WHERE status='AUTHORIZED_FOR_CLERK';

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_user_signup_attempt_mobile_live
ON security.platform_user_signup_attempts (mobile)
WHERE status='AUTHORIZED_FOR_CLERK';

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_user_signup_attempt_clerk_completed
ON security.platform_user_signup_attempts (clerk_user_id)
WHERE clerk_user_id IS NOT NULL;

UPDATE security.security_control_definitions
SET description=(
  'Platform-global one-time human onboarding: Security pre-authorizes with the onboarding key; '
  'Clerk owns password and email OTP verification; Security creates a PENDING USER only after '
  'verified Clerk completion'
),
    introduced_version='1.4.6'
WHERE control_key='admin.global_user_onboarding';

COMMIT;
