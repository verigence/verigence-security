-- Verigence Security DEV — UC-001 Clerk OTP verification bridge
--
-- Clerk's current Backend API requires attempt_verification to receive the exact verification_id
-- returned by prepare_verification. Persist only that provider identifier; OTP values remain
-- transient and are never stored by Security.

BEGIN;

ALTER TABLE security.platform_user_signup_attempts
  ADD COLUMN IF NOT EXISTS clerk_email_verification_id varchar(240);

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_user_signup_attempt_clerk_verification
ON security.platform_user_signup_attempts (clerk_email_verification_id)
WHERE clerk_email_verification_id IS NOT NULL;

UPDATE security.security_control_definitions
SET description=(
  'Platform-global one-time human onboarding: Verigence receives the signup request, Security '
  'validates the onboarding key, creates a banned Clerk identity server-to-server with an internal '
  'verified placeholder, attaches the applicant email as unverified, sends and verifies Clerk email '
  'OTP using the provider verification identifier, promotes the verified applicant email and removes '
  'the placeholder, then creates a PENDING Security USER for administrator approval. Mobile/Web '
  'never calls Clerk and OTP material is never persisted by Security.'
)
WHERE control_key='admin.global_user_onboarding';

COMMIT;
