-- Employee Attendance v2 exception/review rules.
-- Additive to verigence_attendance only.

BEGIN;

ALTER TABLE verigence_attendance.attendance_events
  ADD COLUMN IF NOT EXISTS exception_reason text,
  ADD COLUMN IF NOT EXISTS actor_role varchar(40);

ALTER TABLE verigence_attendance.attendance_days
  ADD COLUMN IF NOT EXISTS hr_review_status varchar(24) NOT NULL DEFAULT 'NOT_REQUIRED',
  ADD COLUMN IF NOT EXISTS hr_review_comment text,
  ADD COLUMN IF NOT EXISTS hr_reviewed_by_user_id uuid,
  ADD COLUMN IF NOT EXISTS hr_reviewed_at_utc timestamptz;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='ck_va_attendance_hr_review_status'
  ) THEN
    ALTER TABLE verigence_attendance.attendance_days
      ADD CONSTRAINT ck_va_attendance_hr_review_status
      CHECK (
        hr_review_status IN ('NOT_REQUIRED','PENDING_HR','APPROVED','ADJUSTED','REJECTED')
      );
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS verigence_attendance.attendance_flags (
  attendance_flag_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  attendance_day_id uuid NOT NULL
    REFERENCES verigence_attendance.attendance_days(attendance_day_id) ON DELETE CASCADE,
  attendance_event_id uuid
    REFERENCES verigence_attendance.attendance_events(attendance_event_id) ON DELETE SET NULL,
  employee_id uuid NOT NULL
    REFERENCES verigence_attendance.employees(employee_id),
  flag_type varchar(40) NOT NULL
    CHECK (flag_type IN ('OUTSIDE_GEOFENCE','LATE_CHECK_IN','EARLY_CHECK_OUT')),
  flag_detail text,
  employee_reason text,
  resolution_status varchar(24) NOT NULL DEFAULT 'PENDING_HR'
    CHECK (resolution_status IN ('PENDING_HR','APPROVED','ADJUSTED','REJECTED')),
  reviewed_by_user_id uuid,
  reviewer_comment text,
  created_at_utc timestamptz NOT NULL DEFAULT now(),
  reviewed_at_utc timestamptz
);

CREATE INDEX IF NOT EXISTS ix_va_attendance_flags_pending
  ON verigence_attendance.attendance_flags(resolution_status,created_at_utc)
  WHERE resolution_status='PENDING_HR';

CREATE INDEX IF NOT EXISTS ix_va_attendance_flags_employee
  ON verigence_attendance.attendance_flags(employee_id,created_at_utc DESC);

INSERT INTO verigence_attendance.module_configuration (
  config_key,config_value_json,updated_at_utc
)
VALUES
  ('attendance.pc_geofence_required','true'::jsonb,now()),
  ('attendance.late_checkin_after_local','"11:00"'::jsonb,now()),
  ('attendance.early_checkout_before_local','"17:00"'::jsonb,now())
ON CONFLICT (config_key) DO NOTHING;

COMMIT;
