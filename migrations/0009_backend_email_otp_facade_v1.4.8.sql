-- Verigence Security — Backend-only Clerk email OTP facade v1.4.8
-- Clerk remains hidden from Mobile/Web. Security stores only Clerk identifiers/state,
-- never password or OTP material.

BEGIN;

ALTER TABLE security.platform_user_signup_attempts
  ADD COLUMN IF NOT EXISTS clerk_email_address_id varchar(240);

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_user_signup_attempt_clerk_email
ON security.platform_user_signup_attempts (clerk_email_address_id)
WHERE clerk_email_address_id IS NOT NULL;

UPDATE security.security_control_definitions
SET description=(
  'Platform-global one-time human onboarding: Verigence receives the signup request, Security '
  'validates the onboarding key, creates a banned Clerk identity server-to-server, forces the '
  'signup email to unverified, sends and verifies Clerk email OTP through the Backend API, then '
  'creates a PENDING Security USER for administrator approval. Mobile/Web never calls Clerk.'
),
    introduced_version='1.4.8'
WHERE control_key='admin.global_user_onboarding';

COMMIT;
