-- Verigence Security DEV — UC-001 registration identity reuse rule.
--
-- Email/mobile ownership blocks a new registration only while the existing USER is ACTIVE or
-- SUSPENDED. Failed, cancelled, expired, rejected, disabled, exited, or other non-owning lifecycle
-- states must not permanently reserve a registration contact value.

BEGIN;

-- Remove both the historical unconditional indexes and any prior revision of the scoped indexes.
DROP INDEX IF EXISTS security.uq_security_users_primary_email_ci;
DROP INDEX IF EXISTS security.uq_security_users_primary_email;
CREATE UNIQUE INDEX uq_security_users_primary_email_ci
ON security.users ((lower(primary_email)))
WHERE primary_email IS NOT NULL
  AND status IN ('ACTIVE','SUSPENDED');

-- Normalize mobile ownership the same way as application validation. The expression prevents
-- formatting variants of the same number from being concurrently owned by ACTIVE/SUSPENDED users.
DROP INDEX IF EXISTS security.uq_security_users_primary_mobile_digits;
DROP INDEX IF EXISTS security.uq_security_users_primary_mobile_digits_active;
CREATE UNIQUE INDEX uq_security_users_primary_mobile_digits_active
ON security.users ((regexp_replace(primary_mobile, '[^0-9]', '', 'g')))
WHERE primary_mobile IS NOT NULL
  AND status IN ('ACTIVE','SUSPENDED');

COMMIT;
