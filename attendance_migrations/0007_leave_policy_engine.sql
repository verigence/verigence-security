-- Professional Employee leave policy model.
-- Additive to verigence_attendance only.

BEGIN;

ALTER TABLE verigence_attendance.leave_types
  ADD COLUMN IF NOT EXISTS min_notice_days integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS max_consecutive_days numeric(6,2),
  ADD COLUMN IF NOT EXISTS requires_reason boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS allow_negative_balance boolean NOT NULL DEFAULT false;

ALTER TABLE verigence_attendance.leave_requests
  ADD COLUMN IF NOT EXISTS day_mode varchar(20) NOT NULL DEFAULT 'FULL_DAY',
  ADD COLUMN IF NOT EXISTS half_day_session varchar(20),
  ADD COLUMN IF NOT EXISTS calculated_days numeric(6,2),
  ADD COLUMN IF NOT EXISTS hr_approved_days numeric(6,2),
  ADD COLUMN IF NOT EXISTS approval_outcome varchar(24),
  ADD COLUMN IF NOT EXISTS cancelled_at_utc timestamptz,
  ADD COLUMN IF NOT EXISTS cancellation_reason text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname='ck_va_leave_day_mode'
  ) THEN
    ALTER TABLE verigence_attendance.leave_requests
      ADD CONSTRAINT ck_va_leave_day_mode
      CHECK (day_mode IN ('FULL_DAY','HALF_DAY'));
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname='ck_va_leave_half_day_session'
  ) THEN
    ALTER TABLE verigence_attendance.leave_requests
      ADD CONSTRAINT ck_va_leave_half_day_session
      CHECK (
        half_day_session IS NULL
        OR half_day_session IN ('FIRST_HALF','SECOND_HALF')
      );
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname='ck_va_leave_approval_outcome'
  ) THEN
    ALTER TABLE verigence_attendance.leave_requests
      ADD CONSTRAINT ck_va_leave_approval_outcome
      CHECK (
        approval_outcome IS NULL
        OR approval_outcome IN ('APPROVED','ADJUSTED','REJECTED')
      );
  END IF;
END $$;

UPDATE verigence_attendance.leave_requests
SET calculated_days=COALESCE(calculated_days,requested_days),
    hr_approved_days=COALESCE(
      hr_approved_days,
      CASE WHEN status='APPROVED' THEN requested_days
           WHEN status='REJECTED' THEN 0
           ELSE NULL END
    ),
    approval_outcome=COALESCE(
      approval_outcome,
      CASE WHEN status='APPROVED' THEN 'APPROVED'
           WHEN status='REJECTED' THEN 'REJECTED'
           ELSE NULL END
    );

COMMIT;
