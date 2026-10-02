-- Employee reimbursement payment lifecycle.
-- Additive only. Existing Attendance and Verigence tables/routes remain unchanged.

BEGIN;

ALTER TABLE verigence_attendance.reimbursement_claims
  ADD COLUMN IF NOT EXISTS payment_status varchar(24) NOT NULL DEFAULT 'NOT_READY',
  ADD COLUMN IF NOT EXISTS payment_initiated_at_utc timestamptz,
  ADD COLUMN IF NOT EXISTS paid_at_utc timestamptz,
  ADD COLUMN IF NOT EXISTS paid_amount numeric(14,2),
  ADD COLUMN IF NOT EXISTS payment_mode varchar(40),
  ADD COLUMN IF NOT EXISTS payment_reference varchar(160),
  ADD COLUMN IF NOT EXISTS payment_processed_by_user_id uuid,
  ADD COLUMN IF NOT EXISTS payment_comment text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname='ck_va_reimbursement_payment_status'
  ) THEN
    ALTER TABLE verigence_attendance.reimbursement_claims
      ADD CONSTRAINT ck_va_reimbursement_payment_status
      CHECK (payment_status IN ('NOT_READY','PENDING','PROCESSING','PAID','FAILED'));
  END IF;
END $$;

UPDATE verigence_attendance.reimbursement_claims
SET payment_status = CASE
  WHEN status='PAID' THEN 'PAID'
  WHEN status='APPROVED' THEN 'PENDING'
  ELSE 'NOT_READY'
END
WHERE payment_status='NOT_READY'
  AND status IN ('APPROVED','PAID');

CREATE INDEX IF NOT EXISTS ix_va_reimbursement_payment_queue
  ON verigence_attendance.reimbursement_claims(payment_status,updated_at_utc DESC)
  WHERE status IN ('APPROVED','PAID');

COMMIT;
