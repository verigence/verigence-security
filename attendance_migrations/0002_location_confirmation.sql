BEGIN;

CREATE TABLE IF NOT EXISTS attendance.location_confirmation (
    location_confirmation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attendance_id uuid NOT NULL REFERENCES attendance.daily_attendance(attendance_id),
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    action varchar(20) NOT NULL CHECK (action IN ('CHECK_IN','CHECK_OUT')),
    latitude numeric(9,6) NOT NULL CHECK (latitude BETWEEN -90 AND 90),
    longitude numeric(9,6) NOT NULL CHECK (longitude BETWEEN -180 AND 180),
    accuracy_m numeric(10,2) NOT NULL CHECK (accuracy_m >= 0),
    captured_at_utc timestamptz NOT NULL,
    display_address text NOT NULL,
    employee_confirmed boolean NOT NULL,
    remarks text,
    created_at_utc timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (attendance_id,action),
    CHECK (employee_confirmed OR length(btrim(COALESCE(remarks,''))) >= 3)
);

CREATE INDEX IF NOT EXISTS ix_attendance_location_confirmation_tenant_user_time
ON attendance.location_confirmation (tenant_id,user_id,created_at_utc DESC);

COMMIT;
