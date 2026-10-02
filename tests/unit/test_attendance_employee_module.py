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


def test_monthly_finance_threshold_is_strictly_over_3000() -> None:
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
