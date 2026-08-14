-- Verigence Security — Phase 1 Self-Onboarding v1.4.5
-- Additive correction to v1.4.2: email is the sign-in identifier, Indian mobile is
-- Verigence-only, and Clerk creation precedes local PENDING USER persistence.

BEGIN;

ALTER TABLE security.users
  ADD COLUMN IF NOT EXISTS first_name varchar(120),
  ADD COLUMN IF NOT EXISTS last_name varchar(120);

-- Phase 1 stores mobile only in canonical +91XXXXXXXXXX form. The functional unique index also
-- protects against formatting differences in any historical/noncanonical rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_security_users_primary_mobile_digits
ON security.users ((regexp_replace(primary_mobile, '[^0-9]', '', 'g')))
WHERE primary_mobile IS NOT NULL;

COMMENT ON COLUMN security.users.primary_email IS
  'Phase 1 human sign-in identifier; globally unique case-insensitively in Security.';
COMMENT ON COLUMN security.users.primary_mobile IS
  'Verigence-only contact number. Phase 1 canonical format is +91XXXXXXXXXX; not sent to Clerk.';
COMMENT ON COLUMN security.users.first_name IS
  'Human first name captured during Phase 1 self-onboarding.';
COMMENT ON COLUMN security.users.last_name IS
  'Human last name captured during Phase 1 self-onboarding.';

COMMIT;
