-- Verigence Security: a person's whole Verigence access paused, and restored (product owner 2026-11-04).
--
-- When a Team Lead has not decided the attendance, leave and claim requests raised in a week by 09:00
-- IST the following Monday, the HR service (myHR) pauses that Team Lead's access to all of Verigence
-- until SuperAdmin restores it from myHR Settings. Security refuses sign-in, "keep me signed in" and
-- session renewal while a pause is active. Every pause and restore is kept. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.user_access_blocks (
  block_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  reason text NOT NULL,
  source text NOT NULL,
  blocked_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  restored_at_utc timestamptz,
  restored_by_user_id uuid,
  restore_note text
);
-- At most one active pause per person.
CREATE UNIQUE INDEX IF NOT EXISTS user_access_blocks_active_uq
  ON security.user_access_blocks (user_id) WHERE restored_at_utc IS NULL;

COMMIT;
