-- Verigence Security — another Verigence app keeps a person signed in on their phone (product owner, 15 Nov 2026)
--
-- SevaSutra on a phone stays signed in for 3 days at most from when the person signed in (product owner: "3 days
-- max, not a month"), without the person signing in again every day. SevaSutra's server asks Security, with its service token and the person's
-- current sign-in, for a long-lived credential for that app; when the person comes back after their short sign-in
-- has run out, the server exchanges it (again with its service token) for a fresh sign-in.
--   * The credential never leaves the app's server; it is kept here only as its hash, is bound to the app's service
--     integration, ends after the app's remember days (3 for SevaSutra), and is revoked when the person signs out of the app.
--   * Separate from security.human_remember_sessions: the Verigence app's own remembered sign-in (one per person per
--     device type) is not touched.
--
-- Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.app_remember_sessions (
  credential_hash   varchar(64) PRIMARY KEY,
  user_id           uuid NOT NULL REFERENCES security.users(user_id),
  client_key        varchar(64) NOT NULL,
  session_id        uuid NOT NULL,
  device_id         uuid NOT NULL,
  created_at_utc    timestamptz NOT NULL,
  expires_at_utc    timestamptz NOT NULL,
  last_used_at_utc  timestamptz NOT NULL,
  revoked_at_utc    timestamptz
);

CREATE INDEX IF NOT EXISTS app_remember_sessions_user_idx ON security.app_remember_sessions (user_id, client_key);

COMMIT;
