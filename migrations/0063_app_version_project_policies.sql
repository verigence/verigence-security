-- Verigence Security: a minimum Verigence app version for one Project (product owner 2026-11-19:
-- "can you enforce it for mahindra team selectively").
--
-- The minimum of 0050 is one value for everyone. This adds a minimum per Project (Tenant): it holds
-- for the people who work in that Project (an ACTIVE operating role there), on the Android app only.
-- From its time on, their app below it is refused at sign-in, at "keep me signed in" and at session
-- renewal, with where to download the latest. People of other Projects are not affected, and web
-- browsers never are. No row for a Project means no minimum of its own. Additive and idempotent.

BEGIN;

CREATE TABLE IF NOT EXISTS security.app_version_project_policies (
  tenant_id uuid PRIMARY KEY REFERENCES security.tenants(tenant_id) ON DELETE CASCADE,
  minimum_version text NOT NULL CHECK (minimum_version ~ '^[0-9]+\.[0-9]+\.[0-9]+$'),
  effective_from_utc timestamptz,
  updated_by_user_id uuid,
  updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMIT;
