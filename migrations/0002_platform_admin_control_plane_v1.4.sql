-- Verigence Security Module — Platform Admin Control Plane v1.4
-- Additive migration. The approved v1.3 baseline remains unchanged.

CREATE TABLE security.platform_admins (
  admin_id uuid PRIMARY KEY,
  username varchar(120) NOT NULL UNIQUE,
  display_name varchar(240) NOT NULL,
  password_hash varchar(500) NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','DISABLED')),
  must_change_password boolean NOT NULL DEFAULT true,
  created_at_utc timestamptz NOT NULL,
  updated_at_utc timestamptz NOT NULL,
  last_login_at_utc timestamptz
);

CREATE INDEX ix_platform_admins_status
ON security.platform_admins(status);
