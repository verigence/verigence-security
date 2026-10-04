-- Verigence Security v2: "Is Employee" flag on users.
-- Additive and idempotent. Unchecked by default; the HR service sets it when a user is created or
-- linked through employee onboarding. Users who register on their own stay unchecked.

BEGIN;

ALTER TABLE security.users
  ADD COLUMN IF NOT EXISTS is_employee boolean NOT NULL DEFAULT false;

COMMIT;
