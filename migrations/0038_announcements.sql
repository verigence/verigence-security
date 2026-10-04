-- Verigence Security v2: announcements shown to people in the apps, and a maintenance notice that
-- blocks the apps for a while. A greeting (WELCOME) or a notice (NOTICE) is shown to a person once,
-- and never more than one a day. MAINTENANCE blocks the apps until ended. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.announcements (
  announcement_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('NOTICE','WELCOME','MAINTENANCE')),
  title text NOT NULL CHECK (length(title) BETWEEN 1 AND 120),
  body text NOT NULL CHECK (length(body) BETWEEN 1 AND 1000),
  back_at_utc timestamptz,
  starts_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  ends_at_utc timestamptz,
  audience text NOT NULL DEFAULT 'EVERYONE' CHECK (audience IN ('EVERYONE','PEOPLE')),
  active boolean NOT NULL DEFAULT true,
  created_by_user_id uuid NOT NULL,
  created_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CHECK (ends_at_utc IS NULL OR ends_at_utc > starts_at_utc)
);

-- Only one maintenance notice can be in force at a time.
CREATE UNIQUE INDEX IF NOT EXISTS announcements_one_active_maintenance
  ON security.announcements (kind) WHERE kind = 'MAINTENANCE' AND active;

CREATE TABLE IF NOT EXISTS security.announcement_people (
  announcement_id uuid NOT NULL REFERENCES security.announcements(announcement_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES security.users(user_id) ON DELETE CASCADE,
  PRIMARY KEY (announcement_id, user_id)
);

CREATE TABLE IF NOT EXISTS security.announcement_seen (
  announcement_id uuid NOT NULL REFERENCES security.announcements(announcement_id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES security.users(user_id) ON DELETE CASCADE,
  seen_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (announcement_id, user_id)
);

CREATE INDEX IF NOT EXISTS announcement_seen_user_ix
  ON security.announcement_seen (user_id, seen_at_utc DESC);

-- How often a person may be shown a notice or greeting at all, set by SuperAdmin. 0 means no limit
-- between them (each is still shown only once per person).
CREATE TABLE IF NOT EXISTS security.announcement_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  quiet_hours integer NOT NULL DEFAULT 20 CHECK (quiet_hours BETWEEN 0 AND 720),
  updated_by_user_id uuid,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO security.announcement_settings (singleton) VALUES (true) ON CONFLICT DO NOTHING;

COMMIT;
