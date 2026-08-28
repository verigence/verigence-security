from __future__ import annotations

from datetime import date
from uuid import UUID

from verigence_security.attendance.schemas import (
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
    records_by_user = {
        UUID(str(row["user_id"])): service._record(row)  # noqa: SLF001
        for row in attendance_rows
    }

    items: list[AttendanceOverviewItem] = []
    checked_in = 0
    checked_out = 0
    exceptions = 0

    for member in roster:
        attendance = records_by_user.get(member.userId)
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

        items.append(
            AttendanceOverviewItem(
                userId=member.userId,
                displayName=member.displayName,
                primaryEmail=member.primaryEmail,
                roleKey=attendance.roleKey if attendance is not None else member.operatingRole,
                status=status,
                attendance=attendance,
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
