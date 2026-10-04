-- Verigence Security v2: optional device diagnostics. Off by default. When SuperAdmin switches it on,
-- apps keep a short on-device log and send it once the person is signed in; SuperAdmin reads it here.
-- Logs are removed after 14 days. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.client_diagnostics_settings (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  enabled boolean NOT NULL DEFAULT false,
  updated_by_user_id uuid,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO security.client_diagnostics_settings (singleton) VALUES (true) ON CONFLICT DO NOTHING;

CREATE TABLE IF NOT EXISTS security.client_diagnostic_logs (
  log_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES security.users(user_id) ON DELETE CASCADE,
  device_id text NOT NULL CHECK (length(device_id) BETWEEN 8 AND 64),
  platform text CHECK (platform IS NULL OR length(platform) <= 20),
  app_version text CHECK (app_version IS NULL OR length(app_version) <= 30),
  entry_count integer NOT NULL CHECK (entry_count BETWEEN 0 AND 100),
  entries jsonb NOT NULL,
  received_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS client_diagnostic_logs_received_ix
  ON security.client_diagnostic_logs (received_at_utc DESC);
CREATE INDEX IF NOT EXISTS client_diagnostic_logs_device_ix
  ON security.client_diagnostic_logs (device_id, received_at_utc DESC);

COMMIT;
