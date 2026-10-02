-- Professional Employee reimbursement model.
-- Additive to verigence_attendance only. Existing Attendance v1 routes/tables are not modified.

BEGIN;

ALTER TABLE verigence_attendance.reimbursement_claims
  ADD COLUMN IF NOT EXISTS claim_number varchar(40),
  ADD COLUMN IF NOT EXISTS purpose varchar(240),
  ADD COLUMN IF NOT EXISTS claim_month date,
  ADD COLUMN IF NOT EXISTS claimed_total numeric(14,2),
  ADD COLUMN IF NOT EXISTS approved_total numeric(14,2),
  ADD COLUMN IF NOT EXISTS adjusted_total numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS approval_outcome varchar(28),
  ADD COLUMN IF NOT EXISTS submitted_at_utc timestamptz;

UPDATE verigence_attendance.reimbursement_claims
SET claim_number = COALESCE(
      claim_number,
      'EXP-' || to_char(expense_date,'YYYYMM') || '-' ||
      upper(substr(replace(claim_id::text,'-',''),1,8))
    ),
    purpose = COALESCE(purpose,description,'Legacy reimbursement'),
    claim_month = COALESCE(claim_month,date_trunc('month',expense_date)::date),
    claimed_total = COALESCE(claimed_total,amount),
    approved_total = COALESCE(
      approved_total,
      CASE
        WHEN status IN ('APPROVED','PAID') THEN amount
        WHEN status='REJECTED' THEN 0
        ELSE NULL
      END
    ),
    adjusted_total = COALESCE(
      adjusted_total,
      CASE
        WHEN status='REJECTED' THEN amount
        ELSE 0
      END
    ),
    submitted_at_utc = COALESCE(submitted_at_utc,created_at_utc);

DO $
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname='ck_va_reimbursement_approval_outcome'
  ) THEN
    ALTER TABLE verigence_attendance.reimbursement_claims
      ADD CONSTRAINT ck_va_reimbursement_approval_outcome
      CHECK (
        approval_outcome IS NULL OR
        approval_outcome IN ('APPROVED','PARTIALLY_APPROVED','REJECTED')
      );
  END IF;
END $;

UPDATE verigence_attendance.reimbursement_claims
SET approval_outcome = CASE
  WHEN status IN ('APPROVED','PAID') AND COALESCE(adjusted_total,0) > 0
    THEN 'PARTIALLY_APPROVED'
  WHEN status IN ('APPROVED','PAID') THEN 'APPROVED'
  WHEN status='REJECTED' THEN 'REJECTED'
  ELSE NULL
END
WHERE approval_outcome IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_va_reimbursement_claim_number
  ON verigence_attendance.reimbursement_claims(claim_number)
  WHERE claim_number IS NOT NULL;

CREATE TABLE IF NOT EXISTS verigence_attendance.reimbursement_items (
  reimbursement_item_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  claim_id uuid NOT NULL
    REFERENCES verigence_attendance.reimbursement_claims(claim_id) ON DELETE CASCADE,
  line_number integer NOT NULL CHECK (line_number > 0),
  expense_date date NOT NULL,
  category varchar(40) NOT NULL
    CHECK (category IN ('TRAVEL','FOOD','LODGING','LOCAL_CONVEYANCE','OTHER')),
  claimed_amount numeric(14,2) NOT NULL CHECK (claimed_amount > 0),
  approved_amount numeric(14,2),
  vendor_name varchar(240),
  description text,
  receipt_object_key varchar(700),
  receipt_sha256 char(64),
  travel_from varchar(240),
  travel_to varchar(240),
  transport_mode varchar(40),
  distance_km numeric(10,2),
  ticket_reference varchar(160),
  meal_type varchar(40),
  line_status varchar(32) NOT NULL DEFAULT 'PENDING_HR'
    CHECK (
      line_status IN (
        'PENDING_HR','PENDING_FINANCE','APPROVED','ADJUSTED','REJECTED'
      )
    ),
  created_at_utc timestamptz NOT NULL DEFAULT now(),
  updated_at_utc timestamptz NOT NULL DEFAULT now(),
  UNIQUE(claim_id,line_number),
  CHECK (approved_amount IS NULL OR approved_amount >= 0),
  CHECK (approved_amount IS NULL OR approved_amount <= claimed_amount)
);

CREATE INDEX IF NOT EXISTS ix_va_reimbursement_items_claim
  ON verigence_attendance.reimbursement_items(claim_id,line_number);

CREATE INDEX IF NOT EXISTS ix_va_reimbursement_items_date
  ON verigence_attendance.reimbursement_items(expense_date,category);

CREATE TABLE IF NOT EXISTS verigence_attendance.reimbursement_item_reviews (
  reimbursement_item_review_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  reimbursement_item_id uuid NOT NULL
    REFERENCES verigence_attendance.reimbursement_items(reimbursement_item_id)
    ON DELETE CASCADE,
  stage varchar(16) NOT NULL CHECK (stage IN ('HR','FINANCE')),
  decision varchar(16) NOT NULL CHECK (decision IN ('APPROVE','ADJUST','REJECT')),
  previous_amount numeric(14,2),
  approved_amount numeric(14,2) NOT NULL CHECK (approved_amount >= 0),
  actor_user_id uuid NOT NULL,
  actor_role varchar(40) NOT NULL,
  comment text,
  decided_at_utc timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ix_va_reimbursement_item_reviews
  ON verigence_attendance.reimbursement_item_reviews(
    reimbursement_item_id,stage,decided_at_utc DESC
  );

-- Backfill existing single-row claims as one professional line item.
INSERT INTO verigence_attendance.reimbursement_items (
  claim_id,line_number,expense_date,category,claimed_amount,approved_amount,
  vendor_name,description,receipt_object_key,receipt_sha256,line_status
)
SELECT
  c.claim_id,
  1,
  c.expense_date,
  CASE
    WHEN c.category IN ('TRAVEL','FOOD','OTHER') THEN c.category
    ELSE 'OTHER'
  END,
  c.amount,
  CASE
    WHEN c.status IN ('APPROVED','PAID') THEN c.amount
    WHEN c.status='REJECTED' THEN 0
    ELSE NULL
  END,
  NULL,
  c.description,
  c.receipt_object_key,
  c.receipt_sha256,
  CASE
    WHEN c.status='PENDING_HR' THEN 'PENDING_HR'
    WHEN c.status='PENDING_FINANCE' THEN 'PENDING_FINANCE'
    WHEN c.status IN ('APPROVED','PAID') THEN 'APPROVED'
    WHEN c.status='REJECTED' THEN 'REJECTED'
    ELSE 'REJECTED'
  END
FROM verigence_attendance.reimbursement_claims c
ON CONFLICT (claim_id,line_number) DO NOTHING;

COMMIT;
