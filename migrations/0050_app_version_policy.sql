-- Verigence Security: the oldest Verigence app version still allowed (product owner 2026-11-04).
--
-- SuperAdmin sets a minimum version for the Android app and, if wanted, the moment it takes effect.
-- From then on an app older than the minimum, or one too old to say its version, cannot sign in,
-- stay signed in or renew its session; the app asks the person to download the latest version.
-- Web browsers are never affected: they always load the current screens. No row value (NULL)
-- means no minimum. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.app_version_policy (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  minimum_version text CHECK (minimum_version IS NULL OR minimum_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  effective_from_utc timestamptz,
  download_url text NOT NULL DEFAULT 'https://verigence-web-dev.jbrconsulting-it.workers.dev/apps',
  updated_by_user_id uuid,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO security.app_version_policy (singleton) VALUES (true) ON CONFLICT DO NOTHING;

COMMIT;
