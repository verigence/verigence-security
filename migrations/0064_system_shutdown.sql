-- Verigence Security: the shutdown switch (product owner 2026-11-21: "lets have a tab in the verigence
-- to have a full shutdown of DB"; "let have superadmin and Executive only the privilege to start the
-- database").
--
-- One row: the daily hours Verigence is shut (India time) and, while it lasts, a Super Admin's or
-- Executive's own "Shut down now" or "Start now". Security reads it once when it starts and again only
-- when one of them changes it, so answering "open or shut" never needs the database. The hours start
-- as the night's sleep every service has gone by since 2026-11-13. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.system_shutdown (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  hours_enabled boolean NOT NULL DEFAULT true,
  hours_from time NOT NULL DEFAULT '00:30',
  hours_to time NOT NULL DEFAULT '08:00',
  manual_state text CHECK (manual_state IN ('SHUT', 'OPEN')),
  manual_until_utc timestamptz,
  changed_by_user_id uuid,
  changed_at_utc timestamptz,
  last_action text,
  CHECK (hours_from <> hours_to),
  CHECK ((manual_state IS NULL) = (manual_until_utc IS NULL))
);

INSERT INTO security.system_shutdown (singleton) VALUES (true) ON CONFLICT (singleton) DO NOTHING;

COMMIT;
