-- Employee reimbursement payment lifecycle.
-- Additive only. Existing Attendance and Verigence tables/routes remain unchanged.
--
-- Employee-facing payment status has only two values:
--   PENDING_PAYMENT -> PROCESSED
-- Payment-rail/transaction failures are finance-internal transaction outcomes and do
-- not change the employee-facing claim payment status.

BEGIN;

ALTER TABLE verigence_attendance.reimbursement_claims
  ADD COLUMN IF NOT EXISTS payment_status varchar(24),
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
      CHECK (
        payment_status IS NULL
        OR payment_status IN ('PENDING_PAYMENT','PROCESSED')
      );
  END IF;
END $$;

UPDATE verigence_attendance.reimbursement_claims
SET payment_status = CASE
  WHEN status='PAID' THEN 'PROCESSED'
  WHEN status='APPROVED' THEN 'PENDING_PAYMENT'
  ELSE NULL
END
WHERE payment_status IS NULL
  AND status IN ('APPROVED','PAID');

CREATE INDEX IF NOT EXISTS ix_va_reimbursement_payment_queue
  ON verigence_attendance.reimbursement_claims(payment_status,updated_at_utc DESC)
  WHERE payment_status='PENDING_PAYMENT';

CREATE TABLE IF NOT EXISTS verigence_attendance.reimbursement_payment_transactions (
  payment_transaction_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id uuid NOT NULL
    REFERENCES verigence_attendance.reimbursement_claims(claim_id),
  transaction_status varchar(20) NOT NULL
    CHECK (transaction_status IN ('INITIATED','SUCCESS','FAILED')),
  amount numeric(14,2),
  payment_mode varchar(40),
  payment_reference varchar(160),
  actor_user_id uuid NOT NULL,
  failure_reason text,
  comment text,
  occurred_at_utc timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_va_reimbursement_payment_txn_claim
  ON verigence_attendance.reimbursement_payment_transactions(
    claim_id,occurred_at_utc DESC
  );

COMMIT;
