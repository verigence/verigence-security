-- India-oriented Employee payroll statutory model.
-- Additive to verigence_attendance only. Existing Verigence/Audit Core data is untouched.

BEGIN;

CREATE TABLE IF NOT EXISTS verigence_attendance.payroll_statutory_config (
  statutory_config_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  effective_from date NOT NULL,
  effective_to date,
  pf_employee_rate numeric(8,6) NOT NULL DEFAULT 0.12,
  pf_employer_rate numeric(8,6) NOT NULL DEFAULT 0.12,
  pf_wage_ceiling numeric(14,2) NOT NULL DEFAULT 25000,
  eps_employer_rate numeric(8,6) NOT NULL DEFAULT 0.0833,
  eps_wage_ceiling numeric(14,2) NOT NULL DEFAULT 15000,
  esi_employee_rate numeric(8,6) NOT NULL DEFAULT 0.0075,
  esi_employer_rate numeric(8,6) NOT NULL DEFAULT 0.0325,
  esi_wage_ceiling numeric(14,2) NOT NULL DEFAULT 21000,
  gratuity_provision_rate numeric(8,6) NOT NULL DEFAULT 0.048077,
  salary_tds_section varchar(40) NOT NULL DEFAULT '392(1)',
  created_at_utc timestamptz NOT NULL DEFAULT now(),
  CHECK (effective_to IS NULL OR effective_to >= effective_from),
  UNIQUE(effective_from)
);

INSERT INTO verigence_attendance.payroll_statutory_config (
  effective_from,pf_employee_rate,pf_employer_rate,pf_wage_ceiling,
  eps_employer_rate,eps_wage_ceiling,esi_employee_rate,esi_employer_rate,
  esi_wage_ceiling,gratuity_provision_rate,salary_tds_section
)
VALUES (
  DATE '2026-04-01',0.12,0.12,25000,
  0.0833,15000,0.0075,0.0325,
  21000,0.048077,'392(1)'
)
ON CONFLICT (effective_from) DO NOTHING;

CREATE TABLE IF NOT EXISTS verigence_attendance.employee_payroll_profiles (
  payroll_profile_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  employee_id uuid NOT NULL REFERENCES verigence_attendance.employees(employee_id),
  effective_from date NOT NULL,
  effective_to date,
  pf_applicable boolean NOT NULL DEFAULT false,
  pf_on_actual_wages boolean NOT NULL DEFAULT false,
  esi_applicable boolean NOT NULL DEFAULT false,
  professional_tax_state varchar(20),
  professional_tax_monthly numeric(14,2) NOT NULL DEFAULT 0,
  tds_monthly numeric(14,2) NOT NULL DEFAULT 0,
  tax_regime varchar(20) NOT NULL DEFAULT 'NEW'
    CHECK (tax_regime IN ('NEW','OLD')),
  gratuity_applicable boolean NOT NULL DEFAULT true,
  uan_masked varchar(40),
  esic_number_masked varchar(40),
  created_by_user_id uuid NOT NULL,
  created_at_utc timestamptz NOT NULL DEFAULT now(),
  updated_at_utc timestamptz NOT NULL DEFAULT now(),
  CHECK (effective_to IS NULL OR effective_to >= effective_from),
  CHECK (professional_tax_monthly >= 0),
  CHECK (tds_monthly >= 0),
  UNIQUE(employee_id,effective_from)
);

CREATE INDEX IF NOT EXISTS ix_va_payroll_profile_effective
  ON verigence_attendance.employee_payroll_profiles(employee_id,effective_from DESC);

ALTER TABLE verigence_attendance.payroll_items
  ADD COLUMN IF NOT EXISTS basic_amount numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS hra_amount numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS allowances_amount numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS other_earnings_amount numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS lop_amount numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS employee_pf numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS employee_esi numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS professional_tax numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS tds_amount numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS other_deductions numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS employer_pf numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS employer_eps numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS employer_esi numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS gratuity_provision numeric(14,2) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS employer_cost numeric(14,2) NOT NULL DEFAULT 0;

COMMIT;
