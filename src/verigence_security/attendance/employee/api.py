from __future__ import annotations

from datetime import UTC, date, datetime
from decimal import Decimal
from io import BytesIO
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy import Connection

from verigence_security.attendance.employee.admin_config import (
    create_holiday,
    create_leave_type,
    create_work_location,
    list_configuration,
    list_holidays,
    list_leave_types,
    list_work_locations,
    update_configuration,
)
from verigence_security.attendance.employee.bulk_import import (
    apply_employee_import,
    build_employee_template,
    preview_employee_workbook,
)
from verigence_security.attendance.employee.db import get_connection
from verigence_security.attendance.employee.errors import AttendanceRuleError
from verigence_security.attendance.employee.payroll import (
    finalize_payroll,
    generate_payroll,
    payroll_items,
    payroll_summary,
)
from verigence_security.attendance.employee.reports import attendance_report, payroll_report
from verigence_security.attendance.employee.repository import (
    attendance_history,
    attendance_supervisory_role,
    create_employee,
    create_leave_request,
    decide_hr_leave,
    decide_reimbursement,
    decide_team_leave,
    employee_for_user,
    leave_balances_for_employee,
    list_employees,
    list_hr_attendance_reviews,
    list_leave_by_status,
    list_leave_for_employee,
    list_payslips,
    list_pm_team_reimbursement_claims,
    list_pm_team_reimbursements,
    list_reimbursement_claims_by_status,
    list_reimbursement_claims_for_employee,
    list_reimbursements_by_payment_status,
    list_reimbursements_by_status,
    list_reimbursements_for_employee,
    list_team_attendance,
    list_team_leave,
    resolve_attendance_review,
    review_reimbursement_claim,
    update_reimbursement_payment,
)
from verigence_security.attendance.employee.schemas import (
    AdminCapabilities,
    AttendanceDayResponse,
    AttendanceEventResponse,
    AttendanceFlagResponse,
    AttendanceHrDecisionRequest,
    AttendanceHrReviewResponse,
    BulkImportResponse,
    ConfigUpdateRequest,
    EmployeeCreateRequest,
    EmployeeProfile,
    HolidayCreateRequest,
    HolidayResponse,
    LeaveBalanceResponse,
    LeaveCreateRequest,
    LeaveDecisionRequest,
    LeaveHrDecisionRequest,
    LeaveRequestResponse,
    LeaveTypeCreateRequest,
    LeaveTypeResponse,
    PayrollItemResponse,
    PayrollSummaryResponse,
    PayslipResponse,
    ReimbursementClaimCreate,
    ReimbursementClaimResponse,
    ReimbursementClaimReviewRequest,
    ReimbursementDecisionRequest,
    ReimbursementLineResponse,
    ReimbursementLineReviewResponse,
    ReimbursementPaymentRequest,
    ReimbursementResponse,
    TeamAttendanceResponse,
    WorkLocationCreateRequest,
    WorkLocationResponse,
)
from verigence_security.attendance.employee.security import HumanPrincipal, human_principal, security_client
from verigence_security.attendance.employee.service import (
    record_attendance,
    submit_reimbursement,
    submit_reimbursement_claim,
)
from verigence_security.attendance.employee.storage import AttendanceStorageError, storage

router = APIRouter(prefix="/employee-attendance/v1", tags=["employee-attendance"])


@router.get("/files/{token}")
def signed_file(
    token: str,
    expires: int = Query(..., ge=1),
    signature: str = Query(..., min_length=64, max_length=64),
) -> StreamingResponse:
    try:
        item = storage().resolve_presigned(
            token=token,
            expires=expires,
            signature=signature,
        )
    except AttendanceStorageError as exc:
        raise AttendanceRuleError(
            "FILE_LINK_INVALID",
            "The requested Attendance file link is invalid or expired.",
            status_code=404,
        ) from exc
    return StreamingResponse(
        BytesIO(item.data),
        media_type=item.content_type,
        headers={"Cache-Control": "private, max-age=60"},
    )


def _employee_profile(row: dict[str, Any]) -> EmployeeProfile:
    return EmployeeProfile(
        employeeId=row["employee_id"],
        securityUserId=row["security_user_id"],
        employeeCode=row["employee_code"],
        displayName=row["display_name"],
        primaryEmail=row.get("primary_email"),
        mobile=row.get("mobile"),
        joiningDate=row["joining_date"],
        employmentStatus=row["employment_status"],
        tlUserId=row.get("tl_user_id"),
        pmoUserId=row.get("pmo_user_id"),
        projectTenantId=row.get("project_tenant_id"),
        workLocationId=row.get("work_location_id"),
        workLocationName=row.get("location_name"),
    )


def _attendance_actor_role(
    connection: Connection,
    principal: HumanPrincipal,
    event_type: str,
) -> str:
    client = security_client()
    if client.allowed(
        user_id=principal.subject,
        permission_key="attendance.exception.resolve",
    ):
        return "HRADMIN"

    employee = employee_for_user(connection, principal.subject)
    tenant_id = employee.get("project_tenant_id")
    if tenant_id is not None:
        permission = (
            "attendance.self.checkin"
            if event_type == "CHECK_IN"
            else "attendance.self.checkout"
        )
        auth = client.require(
            user_id=principal.subject,
            permission_key=permission,
            tenant_id=tenant_id,
        )
        role_key = str(auth.get("roleKey") or "").upper()
        if role_key in {"TL", "PM"}:
            return role_key
        return "PC"

    fallback = attendance_supervisory_role(connection, principal.subject)
    return fallback if fallback in {"TL", "PM"} else "PC"


def _attendance_review(row: dict[str, Any]) -> AttendanceHrReviewResponse:
    return AttendanceHrReviewResponse(
        attendanceDayId=row["attendance_day_id"],
        employeeId=row["employee_id"],
        employeeCode=row["employee_code"],
        employeeName=row["display_name"],
        attendanceDate=row["attendance_date"],
        presentFraction=row["present_fraction"],
        checkInAtUtc=row.get("check_in_at_utc"),
        checkOutAtUtc=row.get("check_out_at_utc"),
        hrReviewStatus=row["hr_review_status"],
        hrReviewComment=row.get("hr_review_comment"),
        flags=[
            AttendanceFlagResponse(
                attendanceFlagId=flag["attendance_flag_id"],
                flagType=flag["flag_type"],
                flagDetail=flag.get("flag_detail"),
                employeeReason=flag.get("employee_reason"),
                resolutionStatus=flag["resolution_status"],
                createdAtUtc=flag["created_at_utc"],
            )
            for flag in row.get("flags", [])
        ],
    )


def _leave(row: dict[str, Any]) -> LeaveRequestResponse:
    return LeaveRequestResponse(
        leaveRequestId=row["leave_request_id"],
        employeeId=row["employee_id"],
        employeeName=row["display_name"],
        leaveTypeId=row["leave_type_id"],
        leaveTypeName=row["leave_name"],
        startDate=row["start_date"],
        endDate=row["end_date"],
        requestedDays=row["requested_days"],
        calculatedDays=row.get("calculated_days") or row["requested_days"],
        dayMode=row.get("day_mode") or "FULL_DAY",
        halfDaySession=row.get("half_day_session"),
        approvedDays=row.get("hr_approved_days"),
        approvalOutcome=row.get("approval_outcome"),
        reason=row.get("reason"),
        status=row["status"],
        createdAtUtc=row["created_at_utc"],
    )


def _claim(row: dict[str, Any]) -> ReimbursementResponse:
    return ReimbursementResponse(
        claimId=row["claim_id"],
        employeeId=row["employee_id"],
        employeeName=row["display_name"],
        expenseDate=row["expense_date"],
        category=row["category"],
        amount=row["amount"],
        description=row.get("description"),
        status=row["status"],
        financeApprovalRequired=bool(row["finance_approval_required"]),
        receiptUrl=(
            storage().presign(object_key=row["receipt_object_key"])
            if row.get("receipt_object_key")
            else None
        ),
        paymentStatus=row.get("payment_status"),
        paidAtUtc=row.get("paid_at_utc"),
        paidAmount=row.get("paid_amount"),
        paymentMode=row.get("payment_mode"),
        paymentReference=row.get("payment_reference"),
        paymentComment=row.get("payment_comment"),
        createdAtUtc=row["created_at_utc"],
    )


def _reimbursement_claim(row: dict[str, Any]) -> ReimbursementClaimResponse:
    lines: list[ReimbursementLineResponse] = []
    for item in row.get("lines", []):
        reviews = [
            ReimbursementLineReviewResponse(
                stage=review["stage"],
                decision=review["decision"],
                previousAmount=review.get("previous_amount"),
                approvedAmount=review["approved_amount"],
                actorRole=review["actor_role"],
                comment=review.get("comment"),
                decidedAtUtc=review["decided_at_utc"],
            )
            for review in item.get("reviews", [])
        ]
        lines.append(
            ReimbursementLineResponse(
                reimbursementItemId=item["reimbursement_item_id"],
                lineNumber=item["line_number"],
                expenseDate=item["expense_date"],
                category=item["category"],
                claimedAmount=item["claimed_amount"],
                approvedAmount=item.get("approved_amount"),
                vendorName=item.get("vendor_name"),
                description=item.get("description"),
                receiptUrl=(
                    storage().presign(object_key=item["receipt_object_key"])
                    if item.get("receipt_object_key")
                    else None
                ),
                travelFrom=item.get("travel_from"),
                travelTo=item.get("travel_to"),
                transportMode=item.get("transport_mode"),
                distanceKm=item.get("distance_km"),
                ticketReference=item.get("ticket_reference"),
                mealType=item.get("meal_type"),
                lineStatus=item["line_status"],
                reviews=reviews,
            )
        )
    return ReimbursementClaimResponse(
        claimId=row["claim_id"],
        claimNumber=row["claim_number"],
        employeeId=row["employee_id"],
        employeeName=row["display_name"],
        purpose=row["purpose"],
        claimMonth=row["claim_month"],
        status=row["status"],
        approvalOutcome=row.get("approval_outcome"),
        financeApprovalRequired=bool(row["finance_approval_required"]),
        claimedTotal=row["claimed_total"],
        approvedTotal=row.get("approved_total"),
        adjustedTotal=row.get("adjusted_total") or Decimal(0),
        paymentStatus=row.get("payment_status"),
        paidAtUtc=row.get("paid_at_utc"),
        paidAmount=row.get("paid_amount"),
        paymentMode=row.get("payment_mode"),
        paymentReference=row.get("payment_reference"),
        paymentComment=row.get("payment_comment"),
        submittedAtUtc=row["submitted_at_utc"],
        lines=lines,
    )


@router.get("/me", response_model=EmployeeProfile)
def my_profile(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> EmployeeProfile:
    return _employee_profile(employee_for_user(connection, principal.subject))


@router.get("/me/attendance", response_model=list[AttendanceDayResponse])
def my_attendance(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    limit: int = Query(default=31, ge=1, le=366),
) -> list[AttendanceDayResponse]:
    employee = employee_for_user(connection, principal.subject)
    rows = attendance_history(
        connection,
        employee_id=UUID(str(employee["employee_id"])),
        limit=limit,
    )
    return [
        AttendanceDayResponse(
            attendanceDayId=row["attendance_day_id"],
            attendanceDate=row["attendance_date"],
            status=row["status"],
            presentFraction=row["present_fraction"],
            checkInAtUtc=row.get("check_in_at_utc"),
            checkOutAtUtc=row.get("check_out_at_utc"),
            hrReviewStatus=row.get("hr_review_status") or "NOT_REQUIRED",
            hrReviewComment=row.get("hr_review_comment"),
        )
        for row in rows
    ]


async def _attendance_action(
    *,
    event_type: str,
    principal: HumanPrincipal,
    connection: Connection,
    latitude: float,
    longitude: float,
    accuracy_meters: float,
    captured_at: datetime,
    photo: UploadFile,
    exception_reason: str | None,
) -> AttendanceEventResponse:
    data = await photo.read()
    actor_role = _attendance_actor_role(connection, principal, event_type)
    result = record_attendance(
        connection,
        user_id=principal.subject,
        event_type=event_type,
        latitude=latitude,
        longitude=longitude,
        accuracy_meters=accuracy_meters,
        captured_at=captured_at,
        photo_data=data,
        photo_content_type=(photo.content_type or "").lower(),
        actor_role=actor_role,
        exception_reason=exception_reason,
        storage=storage(),
    )
    return AttendanceEventResponse.model_validate(result)


@router.post("/me/attendance/check-in", response_model=AttendanceEventResponse)
async def check_in(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    latitude: Annotated[float, Form(ge=-90, le=90)],
    longitude: Annotated[float, Form(ge=-180, le=180)],
    accuracyMeters: Annotated[float, Form(ge=0)],
    capturedAt: Annotated[datetime, Form()],
    photo: Annotated[UploadFile, File(...)],
    exceptionReason: Annotated[str | None, Form(max_length=2000)] = None,
) -> AttendanceEventResponse:
    return await _attendance_action(
        event_type="CHECK_IN",
        principal=principal,
        connection=connection,
        latitude=latitude,
        longitude=longitude,
        accuracy_meters=accuracyMeters,
        captured_at=capturedAt,
        photo=photo,
        exception_reason=exceptionReason,
    )


@router.post("/me/attendance/check-out", response_model=AttendanceEventResponse)
async def check_out(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    latitude: Annotated[float, Form(ge=-90, le=90)],
    longitude: Annotated[float, Form(ge=-180, le=180)],
    accuracyMeters: Annotated[float, Form(ge=0)],
    capturedAt: Annotated[datetime, Form()],
    photo: Annotated[UploadFile, File(...)],
    exceptionReason: Annotated[str | None, Form(max_length=2000)] = None,
) -> AttendanceEventResponse:
    return await _attendance_action(
        event_type="CHECK_OUT",
        principal=principal,
        connection=connection,
        latitude=latitude,
        longitude=longitude,
        accuracy_meters=accuracyMeters,
        captured_at=capturedAt,
        photo=photo,
        exception_reason=exceptionReason,
    )



@router.get("/me/leave-balances", response_model=list[LeaveBalanceResponse])
def my_leave_balances(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[LeaveBalanceResponse]:
    employee = employee_for_user(connection, principal.subject)
    year = datetime.now(UTC).year
    return [
        LeaveBalanceResponse(
            leaveTypeId=row["leave_type_id"],
            leaveCode=row["leave_code"],
            leaveName=row["leave_name"],
            isPaid=row["is_paid"],
            allowHalfDay=row["allow_half_day"],
            openingDays=row["opening_days"],
            entitledDays=row["entitled_days"],
            adjustmentDays=row["adjustment_days"],
            usedDays=row["used_days"],
            availableDays=row["available_days"],
        )
        for row in leave_balances_for_employee(
            connection,
            employee_id=UUID(str(employee["employee_id"])),
            leave_year=year,
        )
    ]

@router.get("/me/leave", response_model=list[LeaveRequestResponse])
def my_leave(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[LeaveRequestResponse]:
    employee = employee_for_user(connection, principal.subject)
    return [
        _leave(row)
        for row in list_leave_for_employee(
            connection,
            UUID(str(employee["employee_id"])),
        )
    ]


@router.post("/me/leave", response_model=LeaveRequestResponse)
def apply_leave(
    body: LeaveCreateRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> LeaveRequestResponse:
    employee = employee_for_user(connection, principal.subject)
    if body.endDate < body.startDate:
        raise AttendanceRuleError(
            "LEAVE_DATES_INVALID",
            "Leave end date cannot be before start date.",
            status_code=400,
        )
    if body.startDate.year != body.endDate.year:
        raise AttendanceRuleError(
            "LEAVE_YEAR_SPAN_UNSUPPORTED",
            "A leave request must stay within one calendar year.",
            status_code=400,
        )
    return _leave(
        create_leave_request(
            connection,
            employee_id=UUID(str(employee["employee_id"])),
            leave_type_id=body.leaveTypeId,
            start_date=body.startDate,
            end_date=body.endDate,
            day_mode=body.dayMode,
            half_day_session=body.halfDaySession,
            reason=body.reason,
        )
    )


@router.get("/team/attendance", response_model=list[TeamAttendanceResponse])
def team_attendance(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    attendanceDate: date | None = None,
) -> list[TeamAttendanceResponse]:
    requested_date = attendanceDate or datetime.now(UTC).date()
    return [
        TeamAttendanceResponse(
            employeeId=row["employee_id"],
            employeeName=row["display_name"],
            attendanceDate=row["attendance_date"] or requested_date,
            status=row["status"] or "NOT_STARTED",
            presentFraction=row["present_fraction"] or Decimal(0),
            checkInAtUtc=row.get("check_in_at_utc"),
            checkOutAtUtc=row.get("check_out_at_utc"),
            hrReviewStatus=row.get("hr_review_status") or "NOT_REQUIRED",
        )
        for row in list_team_attendance(
            connection,
            actor_user_id=principal.subject,
            attendance_date=requested_date,
        )
    ]


@router.get("/team/leave", response_model=list[LeaveRequestResponse])
def team_leave_pending(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[LeaveRequestResponse]:
    return [_leave(row) for row in list_team_leave(connection, principal.subject)]


@router.post("/team/leave/{leave_id}/decision", response_model=LeaveRequestResponse)
def team_leave_decision(
    leave_id: UUID,
    body: LeaveDecisionRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> LeaveRequestResponse:
    return _leave(
        decide_team_leave(
            connection,
            leave_id=leave_id,
            actor_user_id=principal.subject,
            decision=body.decision,
            comment=body.comment,
        )
    )



@router.get(
    "/admin/attendance/reviews",
    response_model=list[AttendanceHrReviewResponse],
)
def hr_attendance_review_queue(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[AttendanceHrReviewResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.exception.resolve",
    )
    return [_attendance_review(row) for row in list_hr_attendance_reviews(connection)]


@router.post(
    "/admin/attendance/{attendance_day_id}/review",
    response_model=AttendanceHrReviewResponse,
)
def hr_attendance_review_decision(
    attendance_day_id: UUID,
    body: AttendanceHrDecisionRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> AttendanceHrReviewResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.exception.resolve",
    )
    return _attendance_review(
        resolve_attendance_review(
            connection,
            attendance_day_id=attendance_day_id,
            actor_user_id=principal.subject,
            decision=body.decision,
            present_fraction=body.presentFraction,
            comment=body.comment,
        )
    )


@router.get("/admin/leave", response_model=list[LeaveRequestResponse])
def hr_leave_queue(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[LeaveRequestResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.leave.hr.approve",
    )
    return [_leave(row) for row in list_leave_by_status(connection, "PENDING_HR")]

@router.post("/admin/leave/{leave_id}/decision", response_model=LeaveRequestResponse)
def hr_leave_decision(
    leave_id: UUID,
    body: LeaveHrDecisionRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> LeaveRequestResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.leave.hr.approve",
    )
    return _leave(
        decide_hr_leave(
            connection,
            leave_id=leave_id,
            actor_user_id=principal.subject,
            decision=body.decision,
            approved_days=body.approvedDays,
            comment=body.comment,
        )
    )


@router.get(
    "/me/reimbursement-claims",
    response_model=list[ReimbursementClaimResponse],
)
def my_reimbursement_claims(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[ReimbursementClaimResponse]:
    employee = employee_for_user(connection, principal.subject)
    return [
        _reimbursement_claim(row)
        for row in list_reimbursement_claims_for_employee(
            connection,
            UUID(str(employee["employee_id"])),
        )
    ]


@router.post(
    "/me/reimbursement-claims",
    response_model=ReimbursementClaimResponse,
)
async def create_my_reimbursement_claim(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    payload: Annotated[str, Form(min_length=2)],
    receipts: Annotated[list[UploadFile] | None, File()] = None,
) -> ReimbursementClaimResponse:
    try:
        request = ReimbursementClaimCreate.model_validate_json(payload)
    except ValidationError as exc:
        raise AttendanceRuleError(
            "REIMBURSEMENT_CLAIM_INVALID",
            "The reimbursement claim contains invalid or incomplete fields.",
            status_code=400,
        ) from exc

    uploaded = receipts or []
    receipt_payloads = [
        (await item.read(), item.content_type)
        for item in uploaded
    ]
    lines = [
        {
            "expense_date": line.expenseDate,
            "category": line.category,
            "claimed_amount": line.claimedAmount,
            "vendor_name": line.vendorName,
            "description": line.description,
            "receipt_index": line.receiptIndex,
            "travel_from": line.travelFrom,
            "travel_to": line.travelTo,
            "transport_mode": line.transportMode,
            "distance_km": line.distanceKm,
            "ticket_reference": line.ticketReference,
            "meal_type": line.mealType,
        }
        for line in request.lines
    ]
    row = submit_reimbursement_claim(
        connection,
        user_id=principal.subject,
        purpose=request.purpose,
        lines=lines,
        receipts=receipt_payloads,
        storage=storage(),
    )
    return _reimbursement_claim(row)


@router.get(
    "/team/reimbursement-claims",
    response_model=list[ReimbursementClaimResponse],
)
def pm_team_reimbursement_claims(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[ReimbursementClaimResponse]:
    return [
        _reimbursement_claim(row)
        for row in list_pm_team_reimbursement_claims(
            connection,
            principal.subject,
        )
    ]


@router.get(
    "/admin/reimbursement-claims",
    response_model=list[ReimbursementClaimResponse],
)
def reimbursement_claim_queue(
    stage: Literal["HR", "FINANCE"],
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[ReimbursementClaimResponse]:
    permission = (
        "attendance.reimbursement.hr.approve"
        if stage == "HR"
        else "attendance.reimbursement.finance.approve"
    )
    security_client().require(user_id=principal.subject, permission_key=permission)
    status = "PENDING_HR" if stage == "HR" else "PENDING_FINANCE"
    return [
        _reimbursement_claim(row)
        for row in list_reimbursement_claims_by_status(connection, status)
    ]


@router.post(
    "/admin/reimbursement-claims/{claim_id}/review",
    response_model=ReimbursementClaimResponse,
)
def reimbursement_claim_review(
    claim_id: UUID,
    stage: Literal["HR", "FINANCE"],
    body: ReimbursementClaimReviewRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> ReimbursementClaimResponse:
    permission = (
        "attendance.reimbursement.hr.approve"
        if stage == "HR"
        else "attendance.reimbursement.finance.approve"
    )
    auth = security_client().require(
        user_id=principal.subject,
        permission_key=permission,
    )
    role = str(auth.get("roleKey") or auth.get("classification") or stage)
    decisions = [
        {
            "reimbursement_item_id": item.reimbursementItemId,
            "decision": item.decision,
            "approved_amount": item.approvedAmount,
            "comment": item.comment,
        }
        for item in body.lineDecisions
    ]
    return _reimbursement_claim(
        review_reimbursement_claim(
            connection,
            claim_id=claim_id,
            actor_user_id=principal.subject,
            actor_role=role,
            stage=stage,
            line_decisions=decisions,
            comment=body.comment,
        )
    )


@router.get("/me/reimbursements", response_model=list[ReimbursementResponse])
def my_reimbursements(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[ReimbursementResponse]:
    employee = employee_for_user(connection, principal.subject)
    return [
        _claim(row)
        for row in list_reimbursements_for_employee(
            connection,
            UUID(str(employee["employee_id"])),
        )
    ]


@router.post("/me/reimbursements", response_model=ReimbursementResponse)
async def create_my_reimbursement(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    expenseDate: Annotated[date, Form()],
    category: Annotated[str, Form(min_length=1, max_length=40)],
    amount: Annotated[Decimal, Form(gt=0)],
    description: Annotated[str | None, Form(max_length=2000)] = None,
    receipt: Annotated[UploadFile | None, File()] = None,
) -> ReimbursementResponse:
    receipt_data = await receipt.read() if receipt is not None else None
    row = submit_reimbursement(
        connection,
        user_id=principal.subject,
        expense_date=expenseDate,
        category=category,
        amount=amount,
        description=description,
        receipt_data=receipt_data,
        receipt_content_type=(receipt.content_type if receipt is not None else None),
        storage=storage(),
    )
    return _claim(row)


@router.get("/team/reimbursements", response_model=list[ReimbursementResponse])
def pm_team_reimbursements(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[ReimbursementResponse]:
    """PM/PMO read-only view of claims for employees explicitly assigned to them."""
    return [
        _claim(row)
        for row in list_pm_team_reimbursements(connection, principal.subject)
    ]


@router.get("/admin/reimbursements", response_model=list[ReimbursementResponse])
def reimbursement_queue(
    stage: Literal["HR", "FINANCE"],
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[ReimbursementResponse]:
    permission = (
        "attendance.reimbursement.hr.approve"
        if stage == "HR"
        else "attendance.reimbursement.finance.approve"
    )
    security_client().require(user_id=principal.subject, permission_key=permission)
    status = "PENDING_HR" if stage == "HR" else "PENDING_FINANCE"
    return [_claim(row) for row in list_reimbursements_by_status(connection, status)]


@router.post(
    "/admin/reimbursements/{claim_id}/decision",
    response_model=ReimbursementResponse,
)
def reimbursement_decision(
    claim_id: UUID,
    stage: Literal["HR", "FINANCE"],
    body: ReimbursementDecisionRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> ReimbursementResponse:
    permission = (
        "attendance.reimbursement.hr.approve"
        if stage == "HR"
        else "attendance.reimbursement.finance.approve"
    )
    auth = security_client().require(user_id=principal.subject, permission_key=permission)
    role = str(auth.get("roleKey") or auth.get("classification") or stage)
    return _claim(
        decide_reimbursement(
            connection,
            claim_id=claim_id,
            actor_user_id=principal.subject,
            actor_role=role,
            stage=stage,
            decision=body.decision,
            comment=body.comment,
        )
    )


@router.get(
    "/admin/reimbursements/payments",
    response_model=list[ReimbursementResponse],
)
def reimbursement_payment_queue(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    paymentStatus: Literal["PENDING_PAYMENT", "PROCESSED"] = "PENDING_PAYMENT",
) -> list[ReimbursementResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.reimbursement.payment.manage",
    )
    return [
        _claim(row)
        for row in list_reimbursements_by_payment_status(connection, paymentStatus)
    ]


@router.post(
    "/admin/reimbursements/{claim_id}/payment",
    response_model=ReimbursementResponse,
)
def reimbursement_payment(
    claim_id: UUID,
    body: ReimbursementPaymentRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> ReimbursementResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.reimbursement.payment.manage",
    )
    return _claim(
        update_reimbursement_payment(
            connection,
            claim_id=claim_id,
            actor_user_id=principal.subject,
            paid_amount=body.paidAmount,
            paid_at_utc=body.paidAtUtc,
            payment_mode=body.paymentMode,
            payment_reference=body.paymentReference,
            comment=body.comment,
        )
    )


@router.get("/me/payslips", response_model=list[PayslipResponse])
def my_payslips(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[PayslipResponse]:
    employee = employee_for_user(connection, principal.subject)
    rows = list_payslips(connection, UUID(str(employee["employee_id"])))
    return [
        PayslipResponse(
            payslipId=row["payslip_id"],
            payrollMonth=row["payroll_month"],
            netAmount=row["net_amount"],
            generatedAtUtc=row["generated_at_utc"],
            downloadUrl=storage().presign(object_key=row["pdf_object_key"]),
        )
        for row in rows
    ]





@router.get("/admin/config")
def admin_config(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> dict[str, object]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    return list_configuration(connection)


@router.put("/admin/config/{config_key}")
def admin_update_config(
    config_key: str,
    body: ConfigUpdateRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> dict[str, object]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    return update_configuration(
        connection,
        key=config_key,
        value=body.value,
        actor_user_id=principal.subject,
    )


@router.get("/admin/work-locations", response_model=list[WorkLocationResponse])
def admin_work_locations(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[WorkLocationResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    return [
        WorkLocationResponse(
            locationId=row["location_id"],
            locationCode=row["location_code"],
            locationName=row["location_name"],
            addressText=row.get("address_text"),
            latitude=row["latitude"],
            longitude=row["longitude"],
            geofenceRadiusMeters=row["geofence_radius_meters"],
            status=row["status"],
        )
        for row in list_work_locations(connection)
    ]


@router.post("/admin/work-locations", response_model=WorkLocationResponse)
def admin_create_work_location(
    body: WorkLocationCreateRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> WorkLocationResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    row = create_work_location(
        connection,
        code=body.locationCode,
        name=body.locationName,
        address=body.addressText,
        latitude=body.latitude,
        longitude=body.longitude,
        radius_meters=body.geofenceRadiusMeters,
    )
    return WorkLocationResponse(
        locationId=row["location_id"],
        locationCode=row["location_code"],
        locationName=row["location_name"],
        addressText=row.get("address_text"),
        latitude=row["latitude"],
        longitude=row["longitude"],
        geofenceRadiusMeters=row["geofence_radius_meters"],
        status=row["status"],
    )


@router.get("/admin/leave-types", response_model=list[LeaveTypeResponse])
def admin_leave_types(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[LeaveTypeResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    return [
        LeaveTypeResponse(
            leaveTypeId=row["leave_type_id"],
            leaveCode=row["leave_code"],
            leaveName=row["leave_name"],
            isPaid=row["is_paid"],
            defaultEntitlementDays=row["default_entitlement_days"],
            allowHalfDay=row["allow_half_day"],
            minNoticeDays=row.get("min_notice_days") or 0,
            maxConsecutiveDays=row.get("max_consecutive_days"),
            requiresReason=bool(row.get("requires_reason", True)),
            allowNegativeBalance=bool(row.get("allow_negative_balance", False)),
            status=row["status"],
        )
        for row in list_leave_types(connection)
    ]


@router.post("/admin/leave-types", response_model=LeaveTypeResponse)
def admin_create_leave_type(
    body: LeaveTypeCreateRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> LeaveTypeResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    row = create_leave_type(
        connection,
        code=body.leaveCode,
        name=body.leaveName,
        is_paid=body.isPaid,
        entitlement_days=body.defaultEntitlementDays,
        allow_half_day=body.allowHalfDay,
        min_notice_days=body.minNoticeDays,
        max_consecutive_days=body.maxConsecutiveDays,
        requires_reason=body.requiresReason,
        allow_negative_balance=body.allowNegativeBalance,
    )
    return LeaveTypeResponse(
        leaveTypeId=row["leave_type_id"],
        leaveCode=row["leave_code"],
        leaveName=row["leave_name"],
        isPaid=row["is_paid"],
        defaultEntitlementDays=row["default_entitlement_days"],
        allowHalfDay=row["allow_half_day"],
        minNoticeDays=row.get("min_notice_days") or 0,
        maxConsecutiveDays=row.get("max_consecutive_days"),
        requiresReason=bool(row.get("requires_reason", True)),
        allowNegativeBalance=bool(row.get("allow_negative_balance", False)),
        status=row["status"],
    )


@router.get("/admin/holidays", response_model=list[HolidayResponse])
def admin_holidays(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[HolidayResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    return [
        HolidayResponse(
            holidayId=row["holiday_id"],
            holidayDate=row["holiday_date"],
            holidayName=row["holiday_name"],
            workLocationId=row.get("work_location_id"),
            status=row["status"],
        )
        for row in list_holidays(connection)
    ]


@router.post("/admin/holidays", response_model=HolidayResponse)
def admin_create_holiday(
    body: HolidayCreateRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> HolidayResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.config.manage",
    )
    row = create_holiday(
        connection,
        holiday_date=body.holidayDate,
        name=body.holidayName,
        work_location_id=body.workLocationId,
    )
    return HolidayResponse(
        holidayId=row["holiday_id"],
        holidayDate=row["holiday_date"],
        holidayName=row["holiday_name"],
        workLocationId=row.get("work_location_id"),
        status=row["status"],
    )

@router.post("/admin/payroll/calculate", response_model=PayrollSummaryResponse)
def calculate_payroll(
    month: date,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> PayrollSummaryResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.payroll.manage",
    )
    return PayrollSummaryResponse.model_validate(
        generate_payroll(
            connection,
            payroll_month=month,
            actor_user_id=principal.subject,
        )
    )


@router.get("/admin/payroll/{run_id}", response_model=PayrollSummaryResponse)
def get_payroll(
    run_id: UUID,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> PayrollSummaryResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.payroll.manage",
    )
    return PayrollSummaryResponse.model_validate(payroll_summary(connection, run_id))


@router.get(
    "/admin/payroll/{run_id}/items",
    response_model=list[PayrollItemResponse],
)
def get_payroll_items(
    run_id: UUID,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[PayrollItemResponse]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.payroll.manage",
    )
    return [
        PayrollItemResponse(
            payrollItemId=row["payroll_item_id"],
            employeeId=row["employee_id"],
            employeeCode=row["employee_code"],
            employeeName=row["display_name"],
            scheduledDays=row["scheduled_days"],
            presentDays=row["present_days"],
            paidLeaveDays=row["paid_leave_days"],
            unpaidLeaveDays=row["unpaid_leave_days"],
            payableDays=row["payable_days"],
            grossAmount=row["gross_amount"],
            deductionAmount=row["deduction_amount"],
            netAmount=row["net_amount"],
        )
        for row in payroll_items(connection, run_id)
    ]


@router.post("/admin/payroll/{run_id}/finalize", response_model=PayrollSummaryResponse)
def finalize_payroll_run(
    run_id: UUID,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> PayrollSummaryResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.payroll.manage",
    )
    return PayrollSummaryResponse.model_validate(
        finalize_payroll(
            connection,
            run_id=run_id,
            actor_user_id=principal.subject,
            storage=storage(),
        )
    )


@router.get("/admin/reports/attendance")
def export_attendance_report(
    startDate: date,
    endDate: date,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> StreamingResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.report.export",
    )
    if endDate < startDate or (endDate - startDate).days > 31:
        raise AttendanceRuleError(
            "REPORT_RANGE_INVALID",
            "Attendance report range must be between 1 and 32 days.",
            status_code=400,
        )
    data = attendance_report(
        connection,
        start_date=startDate,
        end_date=endDate,
    )
    return StreamingResponse(
        BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": (
                f'attachment; filename="attendance-{startDate}-{endDate}.xlsx"'
            )
        },
    )


@router.get("/admin/reports/payroll/{run_id}")
def export_payroll_report(
    run_id: UUID,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> StreamingResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.report.export",
    )
    data = payroll_report(connection, run_id=run_id)
    return StreamingResponse(
        BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": (
                f'attachment; filename="payroll-{run_id}.xlsx"'
            )
        },
    )

@router.get("/admin/capabilities", response_model=AdminCapabilities)
def admin_capabilities(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
) -> AdminCapabilities:
    client = security_client()
    user_id = principal.subject
    return AdminCapabilities(
        employeeManage=client.allowed(user_id=user_id, permission_key="attendance.employee.manage"),
        attendanceReview=client.allowed(
            user_id=user_id,
            permission_key="attendance.exception.resolve",
        ),
        leaveHrApprove=client.allowed(user_id=user_id, permission_key="attendance.leave.hr.approve"),
        reimbursementHrApprove=client.allowed(
            user_id=user_id,
            permission_key="attendance.reimbursement.hr.approve",
        ),
        reimbursementFinanceApprove=client.allowed(
            user_id=user_id,
            permission_key="attendance.reimbursement.finance.approve",
        ),
        reimbursementPaymentManage=client.allowed(
            user_id=user_id,
            permission_key="attendance.reimbursement.payment.manage",
        ),
        payrollManage=client.allowed(user_id=user_id, permission_key="attendance.payroll.manage"),
        reportRead=client.allowed(user_id=user_id, permission_key="attendance.report.read"),
        configManage=client.allowed(user_id=user_id, permission_key="attendance.config.manage"),
    )


@router.get("/admin/employees/import-template")
def employee_import_template(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
) -> StreamingResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.employee.manage",
    )
    data = build_employee_template()
    return StreamingResponse(
        BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": (
                'attachment; filename="verigence-employee-onboarding-template.xlsx"'
            )
        },
    )


@router.post("/admin/employees/imports/preview", response_model=BulkImportResponse)
async def employee_import_preview(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
    workbook: Annotated[UploadFile, File(...)],
) -> BulkImportResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.employee.manage",
    )
    data = await workbook.read()
    if len(data) > 5 * 1024 * 1024:
        raise AttendanceRuleError(
            "IMPORT_TOO_LARGE",
            "Employee onboarding workbook exceeds 5 MB.",
            status_code=400,
        )
    result = preview_employee_workbook(
        connection,
        filename=workbook.filename or "employee-onboarding.xlsx",
        data=data,
        actor_user_id=principal.subject,
    )
    return BulkImportResponse.model_validate(result)


@router.post(
    "/admin/employees/imports/{import_id}/apply",
    response_model=BulkImportResponse,
)
def employee_import_apply(
    import_id: UUID,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> BulkImportResponse:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.employee.manage",
    )
    result = apply_employee_import(
        connection,
        import_id=import_id,
        actor_user_id=principal.subject,
    )
    return BulkImportResponse.model_validate(result)

@router.get("/admin/employees", response_model=list[EmployeeProfile])
def admin_employees(
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> list[EmployeeProfile]:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.employee.manage",
    )
    return [_employee_profile(row) for row in list_employees(connection)]


@router.post("/admin/employees", response_model=EmployeeProfile)
def admin_create_employee(
    body: EmployeeCreateRequest,
    principal: Annotated[HumanPrincipal, Depends(human_principal)],
    connection: Annotated[Connection, Depends(get_connection)],
) -> EmployeeProfile:
    security_client().require(
        user_id=principal.subject,
        permission_key="attendance.employee.manage",
    )
    row = create_employee(
        connection,
        user_id=body.securityUserId,
        employee_code=body.employeeCode,
        display_name=body.displayName,
        primary_email=body.primaryEmail,
        mobile=body.mobile,
        joining_date=body.joiningDate,
        tl_user_id=body.tlUserId,
        pmo_user_id=body.pmoUserId,
        project_tenant_id=body.projectTenantId,
        work_location_id=body.workLocationId,
        bank_account_masked=body.bankAccountMasked,
        pan_masked=body.panMasked,
        aadhaar_masked=body.aadhaarMasked,
        salary={
            "basic_salary": body.basicSalary,
            "hra": body.hra,
            "allowances": body.allowances,
            "other_earnings": body.otherEarnings,
            "fixed_deductions": body.fixedDeductions,
        },
        actor_user_id=principal.subject,
    )
    return _employee_profile(row)
