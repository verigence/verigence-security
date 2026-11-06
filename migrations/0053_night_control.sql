-- Verigence Security: night control (product owner 2026-11-06).
--
-- From 20:00 to 08:30 IST nobody may open Journey 360 or download any Verigence file. The control is on
-- for everyone by default and is kept per feature, so more features can be added later as rows.
-- SuperAdmin and Executive are never blocked. SuperAdmin gives a person access (to one feature or to
-- all of them) with a note; the access stays until SuperAdmin removes it. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.night_control_features (
  feature_key text PRIMARY KEY CHECK (feature_key ~ '^[A-Z][A-Z0-9_]{1,40}$'),
  label text NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  -- India time; a window that starts later than it ends runs over midnight.
  starts_local time NOT NULL DEFAULT '20:00',
  ends_local time NOT NULL DEFAULT '08:30',
  updated_by_user_id uuid,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (starts_local <> ends_local)
);

INSERT INTO security.night_control_features (feature_key, label) VALUES
  ('JOURNEY_360', 'Journey 360'),
  ('FILE_DOWNLOAD', 'File downloads')
ON CONFLICT (feature_key) DO NOTHING;

CREATE TABLE IF NOT EXISTS security.night_access_grants (
  grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  -- NULL: every night-controlled feature.
  feature_key text REFERENCES security.night_control_features (feature_key),
  note text NOT NULL CHECK (length(btrim(note)) >= 3),
  granted_by_user_id uuid NOT NULL,
  granted_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at_utc timestamptz,
  revoked_by_user_id uuid,
  revoke_note text
);

CREATE UNIQUE INDEX IF NOT EXISTS night_access_grants_one_active
  ON security.night_access_grants (user_id, coalesce(feature_key, '*'))
  WHERE revoked_at_utc IS NULL;

COMMIT;
