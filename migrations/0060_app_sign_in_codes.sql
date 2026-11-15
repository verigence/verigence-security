-- Verigence Security — signing in to another Verigence app from the Verigence app (product owner, 15 Nov 2026)
--
-- An employee already signed in on the Verigence app on their phone opens SevaSutra without signing in again:
-- SevaSutra asks the Verigence app, the Verigence app asks the person ("Sign in to SevaSutra as …?") and gets a
-- one-time code here for that app, the app hands it back, and SevaSutra's server exchanges it, with its own
-- service credentials and the PKCE verifier only it holds, for the person's sign-in.
--   * A code is kept only as its hash, lives two minutes, is used once, and is for one app (the service
--     integration that exchanges it) and one redirect.
--   * PKCE (S256): the code alone is useless to whoever intercepts it.
--
-- Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.app_sign_in_codes (
  code_hash         varchar(64) PRIMARY KEY,
  user_id           uuid NOT NULL REFERENCES security.users(user_id),
  client_key        varchar(64) NOT NULL,
  redirect_uri      varchar(300) NOT NULL,
  code_challenge    varchar(128) NOT NULL,
  from_session_id   uuid,
  from_device_id    uuid,
  created_at_utc    timestamptz NOT NULL,
  expires_at_utc    timestamptz NOT NULL,
  used_at_utc       timestamptz
);

CREATE INDEX IF NOT EXISTS app_sign_in_codes_user_idx ON security.app_sign_in_codes (user_id, created_at_utc);

COMMIT;
