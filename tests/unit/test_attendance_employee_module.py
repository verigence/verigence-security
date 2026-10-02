from __future__ import annotations

from decimal import Decimal
from pathlib import Path

from fastapi import APIRouter

from verigence_security.attendance.api import router as attendance_router
from verigence_security.attendance.employee.api import router as employee_router
from verigence_security.attendance.employee.domain import (
    GeoPoint,
    finance_approval_required,
    leave_can_move_to_hr,
    within_geofence,
)

ROOT = Path(__file__).resolve().parents[2]


def _router_paths(router: APIRouter) -> set[str]:
    return {route.path for route in router.routes if hasattr(route, "path")}


def test_existing_and_employee_attendance_routes_coexist() -> None:
    legacy_paths = _router_paths(attendance_router)
    employee_paths = _router_paths(employee_router)
    assert "/attendance/v1/tenants/{tenant_id}/me/today" in legacy_paths
    assert "/employee-attendance/v1/me" in employee_paths
    assert "/employee-attendance/v1/me/attendance/check-in" in employee_paths
    assert "/employee-attendance/v1/admin/payroll/calculate" in employee_paths


def test_deploy_workflow_cannot_create_another_attendance_service() -> None:
    workflow = (ROOT / ".github/workflows/attendance-dev-deploy.yml").read_text(
        encoding="utf-8"
    )
    assert "Require existing Railway Attendance service" in workflow
    assert 'railway add --service "$ATTENDANCE_SERVICE"' not in workflow


def test_employee_schema_is_additive_to_legacy_attendance() -> None:
    migration = (ROOT / "attendance_migrations/0003_employee_module.sql").read_text(
        encoding="utf-8"
    )
    assert "CREATE SCHEMA IF NOT EXISTS verigence_attendance" in migration
    assert "CREATE TABLE IF NOT EXISTS verigence_attendance.employees" in migration
    assert "CREATE TABLE IF NOT EXISTS verigence_attendance.binary_objects" in migration
    assert "ALTER TABLE attendance." not in migration
    assert "DROP TABLE attendance." not in migration


def test_employee_geofence_accepts_within_500m_and_rejects_far_point() -> None:
    office = GeoPoint(30.7333, 76.7794)
    nearby = GeoPoint(30.7340, 76.7800)
    far = GeoPoint(30.7433, 76.7894)
    assert within_geofence(nearby, office, 500)
    assert not within_geofence(far, office, 500)


def test_legacy_single_expense_threshold_helper_remains_compatible() -> None:
    assert not finance_approval_required(Decimal(2500), Decimal(500))
    assert finance_approval_required(Decimal(2500), Decimal(501))


def test_tl_or_pmo_can_move_leave_to_hr() -> None:
    assert leave_can_move_to_hr(tl_approved=True, pmo_approved=False)
    assert leave_can_move_to_hr(tl_approved=False, pmo_approved=True)
    assert not leave_can_move_to_hr(tl_approved=False, pmo_approved=False)


def test_pm_team_reimbursement_is_read_only_and_scoped() -> None:
    repository = (
        ROOT / "src/verigence_security/attendance/employee/repository.py"
    ).read_text(encoding="utf-8")
    api = (ROOT / "src/verigence_security/attendance/employee/api.py").read_text(
        encoding="utf-8"
    )
    assert "e.pmo_user_id=CAST(:actor AS uuid)" in repository
    assert '@router.get("/team/reimbursements"' in api
    assert '@router.post("/team/reimbursements"' not in api



def test_reimbursement_payment_lifecycle_is_auditable() -> None:
    migration = (
        ROOT / "attendance_migrations/0004_reimbursement_payment_lifecycle.sql"
    ).read_text(encoding="utf-8")
    repository = (
        ROOT / "src/verigence_security/attendance/employee/repository.py"
    ).read_text(encoding="utf-8")
    api = (
        ROOT / "src/verigence_security/attendance/employee/api.py"
    ).read_text(encoding="utf-8")
    assert "payment_status" in migration
    assert "paid_at_utc" in migration
    assert "payment_reference" in migration
    assert "reimbursement_payment_transactions" in migration
    assert "def update_reimbursement_payment(" in repository
    assert '"/admin/reimbursements/payments"' in api
    assert '"/admin/reimbursements/{claim_id}/payment"' in api


def test_finance_payment_permission_is_attendance_only() -> None:
    migration = (
        ROOT / "migrations/0034_attendance_reimbursement_payment.sql"
    ).read_text(encoding="utf-8")
    assert "attendance.reimbursement.payment.manage" in migration
    compact = "".join(migration.split())
    assert "'attendance','FINANCEADMIN'" in compact
    assert "audit." not in migration
    assert "di." not in migration



def test_employee_payment_status_has_only_two_states() -> None:
    migration = (
        ROOT / "attendance_migrations/0004_reimbursement_payment_lifecycle.sql"
    ).read_text(encoding="utf-8")
    schemas = (
        ROOT / "src/verigence_security/attendance/employee/schemas.py"
    ).read_text(encoding="utf-8")
    assert "PENDING_PAYMENT" in migration
    assert "PROCESSED" in migration
    assert 'Literal["PENDING_PAYMENT", "PROCESSED"] | None' in schemas
    assert "PROCESSING" not in schemas
    assert "FAILED" not in schemas



def test_v2_finance_threshold_uses_claim_total_only() -> None:
    service = (
        ROOT / "src/verigence_security/attendance/employee/service.py"
    ).read_text(encoding="utf-8")
    professional = service.split("def submit_reimbursement_claim(", 1)[1].split(
        "def submit_reimbursement(", 1
    )[0]
    assert "needs_finance = claimed_total > threshold" in professional
    assert "month_claim_total(" not in professional


def test_v2_processed_payment_must_match_final_approved_total() -> None:
    repository = (
        ROOT / "src/verigence_security/attendance/employee/repository.py"
    ).read_text(encoding="utf-8")
    payment = repository.split("def update_reimbursement_payment(", 1)[1].split(
        "def list_payslips(", 1
    )[0]
    assert 'row.get("approved_total")' in payment
    assert "if paid_amount != approved_total:" in payment


def test_v2_pc_geofence_is_fixed_at_500m() -> None:
    service = (
        ROOT / "src/verigence_security/attendance/employee/service.py"
    ).read_text(encoding="utf-8")
    assert "DEFAULT_GEOFENCE_METERS" in service
    assert 'normalized_role == "PC" and pc_geofence_required' in service


def test_v2_hr_attendance_review_waits_until_checkout() -> None:
    repository = (
        ROOT / "src/verigence_security/attendance/employee/repository.py"
    ).read_text(encoding="utf-8")
    review = repository.split("def list_hr_attendance_reviews(", 1)[1].split(
        "def resolve_attendance_review(", 1
    )[0]
    assert "a.hr_review_status='PENDING_HR'" in review
    assert "a.status='COMPLETED'" in review


def test_v2_payroll_blocks_unresolved_attendance_and_leave() -> None:
    payroll = (
        ROOT / "src/verigence_security/attendance/employee/payroll.py"
    ).read_text(encoding="utf-8")
    assert "def _assert_payroll_ready(" in payroll
    assert "PAYROLL_ATTENDANCE_REVIEW_PENDING" in payroll
    assert "PAYROLL_LEAVE_REVIEW_PENDING" in payroll
    generate = payroll.split("def generate_payroll(", 1)[1].split(
        "def payroll_summary(", 1
    )[0]
    assert "_assert_payroll_ready(connection, month=month)" in generate


def test_v2_reports_include_hr_review_and_statutory_payroll_breakdown() -> None:
    reports = (
        ROOT / "src/verigence_security/attendance/employee/reports.py"
    ).read_text(encoding="utf-8")
    assert '"HR Review Status"' in reports
    assert '"HR Review Comment"' in reports
    assert '"Employee PF"' in reports
    assert '"Employee ESI"' in reports
    assert '"Professional Tax"' in reports
    assert '"Employer Cost"' in reports
