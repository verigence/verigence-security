from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_financeadmin_is_attendance_module_only() -> None:
    migration = (ROOT / "migrations/0033_attendance_financeadmin.sql").read_text()
    assert "('attendance','FINANCEADMIN'" in migration
    assert "attendance.reimbursement.finance.approve" in migration
    assert "audit." not in migration
    assert "di." not in migration


def test_hradmin_does_not_receive_finance_approval() -> None:
    migration = (ROOT / "migrations/0033_attendance_financeadmin.sql").read_text()
    hr_section, finance_section = migration.split(
        "-- FinanceAdmin is a secondary Attendance module role only.",
        maxsplit=1,
    )
    assert "attendance.reimbursement.finance.approve" not in hr_section
    assert "attendance.reimbursement.finance.approve" in finance_section
