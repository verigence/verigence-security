BEGIN;

CREATE SCHEMA IF NOT EXISTS attendance;

CREATE TABLE IF NOT EXISTS attendance.schema_migrations (
    migration_name varchar(160) PRIMARY KEY,
    sha256 char(64) NOT NULL,
    applied_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    applied_by_revision varchar(160) NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance.policy (
    tenant_id uuid PRIMARY KEY,
    timezone_iana varchar(80) NOT NULL DEFAULT 'Asia/Kolkata',
    expected_start_local time NOT NULL DEFAULT '09:00',
    checkin_reminder_local time NOT NULL DEFAULT '08:45',
    expected_end_local time NOT NULL DEFAULT '18:00',
    checkout_reminder_local time NOT NULL DEFAULT '17:45',
    pc_geofence_radius_m integer NOT NULL DEFAULT 300 CHECK (pc_geofence_radius_m BETWEEN 50 AND 5000),
    max_location_accuracy_m numeric(10,2) NOT NULL DEFAULT 150 CHECK (max_location_accuracy_m > 0),
    max_location_age_seconds integer NOT NULL DEFAULT 120 CHECK (max_location_age_seconds BETWEEN 10 AND 900),
    geofence_exception_allowed boolean NOT NULL DEFAULT true,
    updated_by_user_id uuid,
    created_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attendance.daily_attendance (
    attendance_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    attendance_date date NOT NULL,
    role_key varchar(80) NOT NULL,
    status varchar(40) NOT NULL CHECK (status IN (
        'CHECKED_IN','CHECKED_IN_EXCEPTION','CHECKED_OUT','CHECKED_OUT_EXCEPTION','CORRECTED'
    )),
    check_in_at_utc timestamptz NOT NULL,
    check_in_latitude numeric(9,6) NOT NULL CHECK (check_in_latitude BETWEEN -90 AND 90),
    check_in_longitude numeric(9,6) NOT NULL CHECK (check_in_longitude BETWEEN -180 AND 180),
    check_in_accuracy_m numeric(10,2) NOT NULL CHECK (check_in_accuracy_m >= 0),
    check_in_outlet_id uuid,
    check_in_dealer_id uuid,
    check_in_distance_m numeric(12,2),
    check_in_result varchar(40) NOT NULL,
    check_in_exception_reason text,
    check_out_at_utc timestamptz,
    check_out_latitude numeric(9,6),
    check_out_longitude numeric(9,6),
    check_out_accuracy_m numeric(10,2),
    check_out_outlet_id uuid,
    check_out_dealer_id uuid,
    check_out_distance_m numeric(12,2),
    check_out_result varchar(40),
    check_out_exception_reason text,
    corrected_by_user_id uuid,
    correction_reason text,
    created_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id,user_id,attendance_date)
);

CREATE INDEX IF NOT EXISTS ix_attendance_daily_tenant_date
ON attendance.daily_attendance (tenant_id,attendance_date,status);
CREATE INDEX IF NOT EXISTS ix_attendance_daily_user_date
ON attendance.daily_attendance (tenant_id,user_id,attendance_date DESC);

CREATE TABLE IF NOT EXISTS attendance.attendance_event (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attendance_id uuid REFERENCES attendance.daily_attendance(attendance_id),
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    event_type varchar(40) NOT NULL CHECK (event_type IN (
        'CHECK_IN','CHECK_OUT','GEOFENCE_EXCEPTION','CORRECTION'
    )),
    event_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    latitude numeric(9,6),
    longitude numeric(9,6),
    accuracy_m numeric(10,2),
    dealer_id uuid,
    outlet_id uuid,
    distance_m numeric(12,2),
    result_code varchar(60),
    reason text,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS ix_attendance_event_tenant_user_time
ON attendance.attendance_event (tenant_id,user_id,event_at_utc DESC);

CREATE TABLE IF NOT EXISTS attendance.correction (
    correction_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attendance_id uuid NOT NULL REFERENCES attendance.daily_attendance(attendance_id),
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    corrected_by_user_id uuid NOT NULL,
    reason text NOT NULL,
    before_json jsonb NOT NULL,
    after_json jsonb NOT NULL,
    corrected_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMIT;
