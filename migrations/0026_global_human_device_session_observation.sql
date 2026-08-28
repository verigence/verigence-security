-- Global human device/session observation foundation.
-- This layer deliberately remains independent of Tenant context because canonical human login
-- occurs before a project/Tenant is selected. Tenant-scoped Phase-4 device/location enforcement
-- remains authoritative for future operational enforcement.

CREATE TABLE security.human_devices (
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  device_id uuid NOT NULL,
  device_type varchar(20) NOT NULL CHECK (device_type IN ('MOBILE','WEB')),
  platform varchar(30) NOT NULL CHECK (platform IN ('ANDROID','IOS','WINDOWS','MACOS','LINUX','OTHER')),
  device_name varchar(240),
  device_model varchar(160),
  os_version varchar(120),
  browser_name varchar(120),
  browser_version varchar(120),
  app_version varchar(120),
  first_seen_ip inet,
  last_seen_ip inet,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','BLOCKED','REVOKED')),
  first_seen_at_utc timestamptz NOT NULL,
  last_seen_at_utc timestamptz NOT NULL,
  PRIMARY KEY (user_id, device_id)
);

CREATE INDEX ix_human_devices_user_status
ON security.human_devices(user_id, status);

CREATE TABLE security.human_access_sessions (
  access_session_id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES security.users(user_id),
  device_id uuid NOT NULL,
  status varchar(20) NOT NULL CHECK (status IN ('ACTIVE','SUPERSEDED','ENDED','REVOKED')),
  source_ip inet,
  started_at_utc timestamptz NOT NULL,
  token_expires_at_utc timestamptz NOT NULL,
  last_seen_at_utc timestamptz NOT NULL,
  superseded_at_utc timestamptz,
  ended_at_utc timestamptz,
  latitude numeric(9,6),
  longitude numeric(9,6),
  accuracy_meters numeric(10,2),
  geo_source varchar(16) CHECK (geo_source IN ('NATIVE','BROWSER')),
  geo_captured_at_utc timestamptz,
  geo_status varchar(20) NOT NULL DEFAULT 'PENDING'
    CHECK (geo_status IN ('PENDING','AVAILABLE','DENIED','UNAVAILABLE','TIMEOUT')),
  observation_mode varchar(12) NOT NULL DEFAULT 'OBSERVE'
    CHECK (observation_mode IN ('OBSERVE','WARN','ENFORCE')),
  FOREIGN KEY (user_id, device_id)
    REFERENCES security.human_devices(user_id, device_id),
  CHECK (token_expires_at_utc > started_at_utc)
);

CREATE UNIQUE INDEX uq_active_global_human_session
ON security.human_access_sessions(user_id)
WHERE status='ACTIVE';

CREATE INDEX ix_human_access_sessions_user_status
ON security.human_access_sessions(user_id, status, started_at_utc DESC);

CREATE INDEX ix_human_access_sessions_device
ON security.human_access_sessions(user_id, device_id, started_at_utc DESC);
