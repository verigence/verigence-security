from __future__ import annotations

from datetime import date
from uuid import UUID

from verigence_security.attendance.location_confirmation_repository import (
    AttendanceLocationConfirmationRepository,
)
from verigence_security.attendance.schemas import (
    AttendanceLocationConfirmationSummary,
    AttendanceOverviewItem,
    AttendanceOverviewResponse,
)
from verigence_security.attendance.service import AttendanceService


def build_attendance_overview(
    service: AttendanceService,
    *,
    tenant_id: UUID,
    user_id: UUID,
    attendance_date: date,
) -> AttendanceOverviewResponse:
    """Combine the Security active roster with Attendance-owned daily records.

    This executes only on the explicit Attendance overview route. It is never part
    of login, project-context selection, Booking, Delivery, Review, or document work.
    """

    service._authorize(  # noqa: SLF001 - same bounded Attendance application boundary
        user_id=user_id,
        tenant_id=tenant_id,
        permission="attendance.all.read",
    )
    roster = service.security.active_roster(tenant_id=tenant_id)
    attendance_rows = service.repository.tenant_day(
        tenant_id=tenant_id,
        attendance_date=attendance_date,
    )
    rows_by_user = {UUID(str(row["user_id"])): row for row in attendance_rows}
    records_by_user = {
        user: service._record(row)  # noqa: SLF001
        for user, row in rows_by_user.items()
    }
    confirmations_by_attendance = AttendanceLocationConfirmationRepository(
        service.repository.s
    ).for_tenant_day(
        tenant_id=tenant_id,
        attendance_date=attendance_date,
    )

    items: list[AttendanceOverviewItem] = []
    checked_in = 0
    checked_out = 0
    exceptions = 0

    for member in roster:
        attendance = records_by_user.get(member.userId)
        raw_row = rows_by_user.get(member.userId)
        check_in_confirmation: AttendanceLocationConfirmationSummary | None = None
        check_out_confirmation: AttendanceLocationConfirmationSummary | None = None
        if attendance is None:
            status = "NOT_CHECKED_IN"
        else:
            status = attendance.status
            if attendance.checkOutAt is None:
                checked_in += 1
            else:
                checked_out += 1
            if "EXCEPTION" in attendance.status:
                exceptions += 1

            confirmations = confirmations_by_attendance.get(attendance.attendanceId, {})
            if "CHECK_IN" in confirmations:
                check_in_confirmation = AttendanceLocationConfirmationSummary.model_validate(
                    confirmations["CHECK_IN"]
                )
                if (
                    not check_in_confirmation.remarks
                    and raw_row is not None
                    and raw_row.get("check_in_exception_reason")
                ):
                    check_in_confirmation = check_in_confirmation.model_copy(
                        update={"remarks": str(raw_row["check_in_exception_reason"])}
                    )
            if "CHECK_OUT" in confirmations:
                check_out_confirmation = AttendanceLocationConfirmationSummary.model_validate(
                    confirmations["CHECK_OUT"]
                )
                if (
                    not check_out_confirmation.remarks
                    and raw_row is not None
                    and raw_row.get("check_out_exception_reason")
                ):
                    check_out_confirmation = check_out_confirmation.model_copy(
                        update={"remarks": str(raw_row["check_out_exception_reason"])}
                    )

        items.append(
            AttendanceOverviewItem(
                userId=member.userId,
                displayName=member.displayName,
                primaryEmail=member.primaryEmail,
                roleKey=attendance.roleKey if attendance is not None else member.operatingRole,
                status=status,
                attendance=attendance,
                checkInLocationConfirmation=check_in_confirmation,
                checkOutLocationConfirmation=check_out_confirmation,
            )
        )

    return AttendanceOverviewResponse(
        attendanceDate=attendance_date,
        totalEmployees=len(items),
        checkedIn=checked_in,
        checkedOut=checked_out,
        notCheckedIn=sum(1 for item in items if item.attendance is None),
        exceptions=exceptions,
        items=items,
    )
