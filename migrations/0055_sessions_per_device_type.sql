-- Verigence Security v2 (0055): one signed-in session per user PER DEVICE TYPE (product owner,
-- 7 Nov 2026). A person may stay signed in on one phone (the Android app, MOBILE) and one PC
-- browser (WEB) at the same time. A new sign-in on another phone still ends the previous phone's
-- session and its "Keep me signed in"; a new sign-in on another browser still ends the previous
-- browser's. Until now any new sign-in ended every other session of the person, so signing in on
-- the PC knocked the phone out (and the other way round).
--
-- Both tables get the device type of their session. Live access sessions take it from their
-- device row (the foreign key guarantees one exists). A remembered sign-in whose device was never
-- recorded cannot be classified: an ACTIVE one is revoked here (none on DEV on 7 Nov 2026), older
-- ones keep NULL as history. Additive; safe to re-run.

BEGIN;

-- Access sessions --------------------------------------------------------------------------------
ALTER TABLE security.human_access_sessions ADD COLUMN IF NOT EXISTS device_type varchar(20);

UPDATE security.human_access_sessions s
SET device_type = d.device_type
FROM security.human_devices d
WHERE d.user_id = s.user_id AND d.device_id = s.device_id AND s.device_type IS NULL;

ALTER TABLE security.human_access_sessions ALTER COLUMN device_type SET NOT NULL;
ALTER TABLE security.human_access_sessions DROP CONSTRAINT IF EXISTS human_access_sessions_device_type_check;
ALTER TABLE security.human_access_sessions
  ADD CONSTRAINT human_access_sessions_device_type_check CHECK (device_type IN ('MOBILE','WEB'));

DROP INDEX IF EXISTS security.uq_active_global_human_session;
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_human_session_per_device_type
  ON security.human_access_sessions (user_id, device_type)
  WHERE status = 'ACTIVE';

-- Remembered sign-ins ("Keep me signed in") ----------------------------------------------------
ALTER TABLE security.human_remember_sessions ADD COLUMN IF NOT EXISTS device_type varchar(20);

UPDATE security.human_remember_sessions r
SET device_type = d.device_type
FROM security.human_devices d
WHERE d.user_id = r.user_id AND d.device_id = r.device_id AND r.device_type IS NULL;

UPDATE security.human_remember_sessions
SET status = 'REVOKED', revoked_at_utc = CURRENT_TIMESTAMP
WHERE status = 'ACTIVE' AND device_type IS NULL;

ALTER TABLE security.human_remember_sessions DROP CONSTRAINT IF EXISTS human_remember_sessions_device_type_check;
ALTER TABLE security.human_remember_sessions
  ADD CONSTRAINT human_remember_sessions_device_type_check
  CHECK (CASE WHEN device_type IS NULL THEN status <> 'ACTIVE' ELSE device_type IN ('MOBILE','WEB') END);

DROP INDEX IF EXISTS security.uq_active_human_remember_session;
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_human_remember_per_device_type
  ON security.human_remember_sessions (user_id, device_type)
  WHERE status = 'ACTIVE';

-- A writer that does not name the device type (the previous Security release, still serving for
-- the minute of the deploy) gets it from the device row, so the deploy has no failing window.
CREATE OR REPLACE FUNCTION security.fill_session_device_type() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.device_type IS NULL THEN
    SELECT d.device_type INTO NEW.device_type
    FROM security.human_devices d
    WHERE d.user_id = NEW.user_id AND d.device_id = NEW.device_id;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_human_access_sessions_device_type ON security.human_access_sessions;
CREATE TRIGGER trg_human_access_sessions_device_type
  BEFORE INSERT ON security.human_access_sessions
  FOR EACH ROW EXECUTE FUNCTION security.fill_session_device_type();

DROP TRIGGER IF EXISTS trg_human_remember_sessions_device_type ON security.human_remember_sessions;
CREATE TRIGGER trg_human_remember_sessions_device_type
  BEFORE INSERT ON security.human_remember_sessions
  FOR EACH ROW EXECUTE FUNCTION security.fill_session_device_type();

COMMIT;
