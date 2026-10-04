-- Verigence Security v2: step-by-step launch of screens. A feature (Audit, Analytics) is hidden
-- until it is switched on, either for everyone or for chosen people. Nothing here grants data
-- access; it only decides which sections the web and mobile apps show. SuperAdmin always sees all.
-- Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.feature_access (
  feature_key text NOT NULL CHECK (feature_key IN ('AUDIT','ANALYTICS')),
  user_id uuid REFERENCES security.users(user_id) ON DELETE CASCADE,
  enabled boolean NOT NULL,
  updated_by_user_id uuid NOT NULL,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- user_id NULL is the "everyone" setting; a person's own row wins over it.
CREATE UNIQUE INDEX IF NOT EXISTS feature_access_scope_uq
  ON security.feature_access (feature_key, COALESCE(user_id, '00000000-0000-0000-0000-000000000000'::uuid));

COMMIT;
