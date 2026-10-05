-- Verigence Security v2: who tried to sign in, and who downloaded the Android app.
-- One row per sign-in attempt (success or failure) and one row per APK download. No password is ever
-- stored. Read by SuperAdmin (Login activity report). Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.login_attempts (
  attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  attempted_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  identifier text CHECK (identifier IS NULL OR length(identifier) <= 320),
  user_id uuid REFERENCES security.users(user_id) ON DELETE SET NULL,
  outcome text NOT NULL CHECK (outcome IN ('SUCCESS','FAILED')),
  reason text CHECK (reason IS NULL OR length(reason) <= 80),
  device_type text CHECK (device_type IS NULL OR length(device_type) <= 12),
  platform text CHECK (platform IS NULL OR length(platform) <= 20),
  app_version text CHECK (app_version IS NULL OR length(app_version) <= 30),
  source_ip text CHECK (source_ip IS NULL OR length(source_ip) <= 64)
);

CREATE INDEX IF NOT EXISTS login_attempts_time_ix ON security.login_attempts (attempted_at_utc DESC);
CREATE INDEX IF NOT EXISTS login_attempts_user_ix ON security.login_attempts (user_id, attempted_at_utc DESC);
CREATE INDEX IF NOT EXISTS login_attempts_identifier_ix ON security.login_attempts (identifier);

CREATE TABLE IF NOT EXISTS security.app_downloads (
  download_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  downloaded_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id uuid NOT NULL REFERENCES security.users(user_id) ON DELETE CASCADE,
  app_version text CHECK (app_version IS NULL OR length(app_version) <= 30),
  source_ip text CHECK (source_ip IS NULL OR length(source_ip) <= 64)
);

CREATE INDEX IF NOT EXISTS app_downloads_user_ix ON security.app_downloads (user_id, downloaded_at_utc DESC);

COMMIT;
