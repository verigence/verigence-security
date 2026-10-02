from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, text
from sqlalchemy.exc import IntegrityError

from verigence_security.attendance.employee.errors import (
    AttendanceNotFoundError,
    AttendanceRuleError,
)


def employee_for_user(connection: Connection, user_id: str) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT e.*,w.location_name,w.latitude AS work_latitude,
                   w.longitude AS work_longitude,w.geofence_radius_meters,
                   w.status AS work_location_status
            FROM verigence_attendance.employees e
            LEFT JOIN verigence_attendance.work_locations w
              ON w.location_id=e.work_location_id
            WHERE e.security_user_id=CAST(:user_id AS uuid)
            """
        ),
        {"user_id": user_id},
    ).mappings().first()
    if row is None or row["employment_status"] != "ACTIVE":
        raise AttendanceNotFoundError("Active employee profile not found.")
    return dict(row)


def employee_by_id(connection: Connection, employee_id: UUID) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT e.*,w.location_name,w.latitude AS work_latitude,
                   w.longitude AS work_longitude,w.geofence_radius_meters,
                   w.status AS work_location_status
            FROM verigence_attendance.employees e
            LEFT JOIN verigence_attendance.work_locations w
              ON w.location_id=e.work_location_id
            WHERE e.employee_id=:employee_id
            """
        ),
        {"employee_id": employee_id},
    ).mappings().first()
    if row is None:
        raise AttendanceNotFoundError("Employee not found.")
    return dict(row)


def list_employees(connection: Connection) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT e.*,w.location_name
                FROM verigence_attendance.employees e
                LEFT JOIN verigence_attendance.work_locations w
                  ON w.location_id=e.work_location_id
                ORDER BY lower(e.display_name),e.employee_code
                """
            )
        ).mappings()
    ]


def create_employee(
    connection: Connection,
    *,
    user_id: UUID,
    employee_code: str,
    display_name: str,
    primary_email: str | None,
    mobile: str | None,
    joining_date: date,
    tl_user_id: UUID | None,
    pmo_user_id: UUID | None,
    project_tenant_id: UUID | None,
    work_location_id: UUID | None,
    bank_account_masked: str | None,
    pan_masked: str | None,
    aadhaar_masked: str | None,
    salary: dict[str, Decimal],
    actor_user_id: str,
) -> dict[str, Any]:
    if work_location_id is not None:
        exists = connection.execute(
            text(
                """
                SELECT 1 FROM verigence_attendance.work_locations
                WHERE location_id=:location_id AND status='ACTIVE'
                """
            ),
            {"location_id": work_location_id},
        ).scalar_one_or_none()
        if exists is None:
            raise AttendanceRuleError(
                "WORK_LOCATION_INVALID",
                "Selected work location is not active.",
                status_code=400,
            )
    employee_id = uuid4()
    try:
        connection.execute(
            text(
                """
                INSERT INTO verigence_attendance.employees (
                    employee_id,security_user_id,employee_code,display_name,
                    primary_email,mobile,joining_date,tl_user_id,pmo_user_id,
                    project_tenant_id,work_location_id,
                    bank_account_masked,pan_masked,aadhaar_masked
                ) VALUES (
                    :employee_id,:security_user_id,:employee_code,:display_name,
                    :primary_email,:mobile,:joining_date,:tl_user_id,:pmo_user_id,
                    :project_tenant_id,:work_location_id,
                    :bank_account_masked,:pan_masked,:aadhaar_masked
                )
                """
            ),
            {
                "employee_id": employee_id,
                "security_user_id": user_id,
                "employee_code": employee_code.strip(),
                "display_name": display_name.strip(),
                "primary_email": primary_email,
                "mobile": mobile,
                "joining_date": joining_date,
                "tl_user_id": tl_user_id,
                "pmo_user_id": pmo_user_id,
                "project_tenant_id": project_tenant_id,
                "work_location_id": work_location_id,
                "bank_account_masked": bank_account_masked,
                "pan_masked": pan_masked,
                "aadhaar_masked": aadhaar_masked,
            },
        )
    except IntegrityError as exc:
        raise AttendanceRuleError(
            "EMPLOYEE_ALREADY_EXISTS",
            "Employee code or Security user is already onboarded.",
            status_code=409,
        ) from exc

    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.salary_structures (
                employee_id,effective_from,basic_salary,hra,allowances,
                other_earnings,fixed_deductions,created_by_user_id
            ) VALUES (
                :employee_id,:effective_from,:basic_salary,:hra,:allowances,
                :other_earnings,:fixed_deductions,CAST(:actor AS uuid)
            )
            """
        ),
        {
            "employee_id": employee_id,
            "effective_from": joining_date,
            **salary,
            "actor": actor_user_id,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.leave_balances (
                employee_id,leave_type_id,leave_year,opening_days,
                entitled_days,adjustment_days,used_days
            )
            SELECT :employee_id,leave_type_id,:leave_year,0,
                   default_entitlement_days,0,0
            FROM verigence_attendance.leave_types
            WHERE status='ACTIVE'
            ON CONFLICT (employee_id,leave_type_id,leave_year) DO NOTHING
            """
        ),
        {"employee_id": employee_id, "leave_year": joining_date.year},
    )
    return employee_by_id(connection, employee_id)



def attendance_supervisory_role(connection: Connection, user_id: str) -> str:
    row = connection.execute(
        text(
            """
            SELECT
              EXISTS(
                SELECT 1 FROM verigence_attendance.employees
                WHERE employment_status='ACTIVE'
                  AND pmo_user_id=CAST(:actor AS uuid)
              ) AS is_pm,
              EXISTS(
                SELECT 1 FROM verigence_attendance.employees
                WHERE employment_status='ACTIVE'
                  AND tl_user_id=CAST(:actor AS uuid)
              ) AS is_tl
            """
        ),
        {"actor": user_id},
    ).mappings().one()
    if bool(row["is_pm"]):
        return "PM"
    if bool(row["is_tl"]):
        return "TL"
    return "PC"


def attendance_rule_config(connection: Connection) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "attendance.pc_geofence_required": True,
        "attendance.late_checkin_after_local": "11:00",
        "attendance.early_checkout_before_local": "17:00",
    }
    rows = connection.execute(
        text(
            """
            SELECT config_key,config_value_json
            FROM verigence_attendance.module_configuration
            WHERE config_key IN (
              'attendance.pc_geofence_required',
              'attendance.late_checkin_after_local',
              'attendance.early_checkout_before_local'
            )
            """
        )
    ).mappings()
    for row in rows:
        defaults[str(row["config_key"])] = row["config_value_json"]
    return defaults


def insert_attendance_flag(
    connection: Connection,
    *,
    attendance_day_id: UUID,
    attendance_event_id: UUID,
    employee_id: UUID,
    flag_type: str,
    flag_detail: str,
    employee_reason: str | None,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.attendance_flags (
                attendance_day_id,attendance_event_id,employee_id,
                flag_type,flag_detail,employee_reason
            ) VALUES (
                :day_id,:event_id,:employee_id,:flag_type,:flag_detail,:employee_reason
            )
            """
        ),
        {
            "day_id": attendance_day_id,
            "event_id": attendance_event_id,
            "employee_id": employee_id,
            "flag_type": flag_type,
            "flag_detail": flag_detail,
            "employee_reason": employee_reason,
        },
    )
    connection.execute(
        text(
            """
            UPDATE verigence_attendance.attendance_days
            SET hr_review_status='PENDING_HR',updated_at_utc=now()
            WHERE attendance_day_id=:day_id
            """
        ),
        {"day_id": attendance_day_id},
    )


def list_hr_attendance_reviews(connection: Connection) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    days = connection.execute(
        text(
            """
            SELECT a.*,e.display_name,e.employee_code
            FROM verigence_attendance.attendance_days a
            JOIN verigence_attendance.employees e ON e.employee_id=a.employee_id
            WHERE a.hr_review_status='PENDING_HR'
              AND a.status='COMPLETED'
            ORDER BY a.attendance_date,a.created_at_utc
            """
        )
    ).mappings()
    for row in days:
        item = dict(row)
        item["flags"] = [
            dict(flag)
            for flag in connection.execute(
                text(
                    """
                    SELECT attendance_flag_id,flag_type,flag_detail,
                           employee_reason,resolution_status,created_at_utc
                    FROM verigence_attendance.attendance_flags
                    WHERE attendance_day_id=:day_id
                    ORDER BY created_at_utc
                    """
                ),
                {"day_id": item["attendance_day_id"]},
            ).mappings()
        ]
        result.append(item)
    return result


def resolve_attendance_review(
    connection: Connection,
    *,
    attendance_day_id: UUID,
    actor_user_id: str,
    decision: str,
    present_fraction: Decimal | None,
    comment: str | None,
) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT a.*,e.display_name,e.employee_code
            FROM verigence_attendance.attendance_days a
            JOIN verigence_attendance.employees e ON e.employee_id=a.employee_id
            WHERE a.attendance_day_id=:day_id
            FOR UPDATE
            """
        ),
        {"day_id": attendance_day_id},
    ).mappings().first()
    if row is None:
        raise AttendanceNotFoundError("Attendance day not found.")
    if row["hr_review_status"] != "PENDING_HR":
        raise AttendanceRuleError(
            "ATTENDANCE_REVIEW_STATE_INVALID",
            "Attendance is not awaiting HR review.",
            status_code=409,
        )

    normalized_comment = (comment or "").strip() or None
    if decision in {"ADJUST", "REJECT"} and not normalized_comment:
        raise AttendanceRuleError(
            "ATTENDANCE_REVIEW_COMMENT_REQUIRED",
            "A reason is required when attendance is adjusted or rejected.",
            status_code=400,
        )
    if decision == "APPROVE":
        review_status = "APPROVED"
        credited = Decimal(str(row["present_fraction"]))
    elif decision == "REJECT":
        review_status = "REJECTED"
        credited = Decimal(0)
    else:
        if present_fraction is None or present_fraction < 0 or present_fraction > 1:
            raise AttendanceRuleError(
                "ATTENDANCE_CREDIT_INVALID",
                "Adjusted attendance credit must be between 0 and 1.",
                status_code=400,
            )
        review_status = "ADJUSTED"
        credited = present_fraction

    connection.execute(
        text(
            """
            UPDATE verigence_attendance.attendance_days
            SET hr_review_status=:review_status,
                present_fraction=:present_fraction,
                hr_review_comment=:comment,
                hr_reviewed_by_user_id=CAST(:actor AS uuid),
                hr_reviewed_at_utc=now(),
                updated_at_utc=now()
            WHERE attendance_day_id=:day_id
            """
        ),
        {
            "review_status": review_status,
            "present_fraction": credited,
            "comment": normalized_comment,
            "actor": actor_user_id,
            "day_id": attendance_day_id,
        },
    )
    connection.execute(
        text(
            """
            UPDATE verigence_attendance.attendance_flags
            SET resolution_status=:review_status,
                reviewed_by_user_id=CAST(:actor AS uuid),
                reviewer_comment=:comment,
                reviewed_at_utc=now()
            WHERE attendance_day_id=:day_id
              AND resolution_status='PENDING_HR'
            """
        ),
        {
            "review_status": review_status,
            "actor": actor_user_id,
            "comment": normalized_comment,
            "day_id": attendance_day_id,
        },
    )
    updated = dict(row)
    updated["hr_review_status"] = review_status
    updated["present_fraction"] = credited
    updated["hr_review_comment"] = normalized_comment
    updated["flags"] = [
        dict(flag)
        for flag in connection.execute(
            text(
                """
                SELECT attendance_flag_id,flag_type,flag_detail,
                       employee_reason,resolution_status,created_at_utc
                FROM verigence_attendance.attendance_flags
                WHERE attendance_day_id=:day_id
                ORDER BY created_at_utc
                """
            ),
            {"day_id": attendance_day_id},
        ).mappings()
    ]
    return updated


def attendance_history(
    connection: Connection,
    *,
    employee_id: UUID,
    limit: int = 31,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT attendance_day_id,attendance_date,status,present_fraction,
                       check_in_at_utc,check_out_at_utc,hr_review_status,
                       hr_review_comment
                FROM verigence_attendance.attendance_days
                WHERE employee_id=:employee_id
                ORDER BY attendance_date DESC
                LIMIT :limit
                """
            ),
            {"employee_id": employee_id, "limit": limit},
        ).mappings()
    ]


def lock_attendance_day(
    connection: Connection,
    *,
    employee_id: UUID,
    attendance_date: date,
) -> dict[str, Any]:
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.attendance_days (
                employee_id,attendance_date,status,present_fraction
            ) VALUES (:employee_id,:attendance_date,'NOT_STARTED',0)
            ON CONFLICT (employee_id,attendance_date) DO NOTHING
            """
        ),
        {"employee_id": employee_id, "attendance_date": attendance_date},
    )
    row = connection.execute(
        text(
            """
            SELECT * FROM verigence_attendance.attendance_days
            WHERE employee_id=:employee_id AND attendance_date=:attendance_date
            FOR UPDATE
            """
        ),
        {"employee_id": employee_id, "attendance_date": attendance_date},
    ).mappings().one()
    return dict(row)


def insert_attendance_event(
    connection: Connection,
    *,
    attendance_day_id: UUID,
    employee_id: UUID,
    event_id: UUID,
    event_type: str,
    captured_at: datetime,
    latitude: float,
    longitude: float,
    accuracy_meters: float,
    work_location_id: UUID | None,
    distance_meters: float | None,
    radius_meters: int | None,
    geofence_result: str,
    exception_reason: str | None,
    actor_role: str,
    photo_object_key: str,
    photo_sha256: str,
) -> None:
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.attendance_events (
                attendance_event_id,attendance_day_id,employee_id,event_type,
                captured_at_utc,latitude,longitude,accuracy_meters,work_location_id,
                distance_meters,geofence_radius_meters,geofence_result,
                exception_reason,actor_role,
                photo_object_key,photo_sha256,capture_source
            ) VALUES (
                :event_id,:day_id,:employee_id,:event_type,:captured_at,
                :latitude,:longitude,:accuracy,:work_location_id,:distance,
                :radius,:geofence_result,:exception_reason,:actor_role,
                :photo_key,:photo_sha256,'LIVE_CAMERA'
            )
            """
        ),
        {
            "event_id": event_id,
            "day_id": attendance_day_id,
            "employee_id": employee_id,
            "event_type": event_type,
            "captured_at": captured_at,
            "latitude": latitude,
            "longitude": longitude,
            "accuracy": accuracy_meters,
            "work_location_id": work_location_id,
            "distance": distance_meters,
            "radius": radius_meters,
            "geofence_result": geofence_result,
            "exception_reason": exception_reason,
            "actor_role": actor_role,
            "photo_key": photo_object_key,
            "photo_sha256": photo_sha256,
        },
    )


def update_attendance_day(
    connection: Connection,
    *,
    attendance_day_id: UUID,
    event_type: str,
    captured_at: datetime,
) -> None:
    if event_type == "CHECK_IN":
        connection.execute(
            text(
                """
                UPDATE verigence_attendance.attendance_days
                SET check_in_at_utc=:captured_at,status='CHECKED_IN',
                    present_fraction=0,updated_at_utc=now()
                WHERE attendance_day_id=:day_id
                """
            ),
            {"captured_at": captured_at, "day_id": attendance_day_id},
        )
    else:
        connection.execute(
            text(
                """
                UPDATE verigence_attendance.attendance_days
                SET check_out_at_utc=:captured_at,status='COMPLETED',
                    present_fraction=1,updated_at_utc=now()
                WHERE attendance_day_id=:day_id
                """
            ),
            {"captured_at": captured_at, "day_id": attendance_day_id},
        )


def _leave_scheduled_days(
    connection: Connection,
    *,
    employee_id: UUID,
    start_date: date,
    end_date: date,
) -> list[date]:
    employee = employee_by_id(connection, employee_id)
    config = connection.execute(
        text(
            """
            SELECT config_value_json
            FROM verigence_attendance.module_configuration
            WHERE config_key='payroll.weekly_off_iso_weekdays'
            """
        )
    ).scalar_one_or_none()
    weekly_offs = {7}
    if isinstance(config, list):
        weekly_offs = {
            int(value)
            for value in config
            if isinstance(value, (int, float, str)) and 1 <= int(value) <= 7
        } or {7}

    holidays = set(
        connection.execute(
            text(
                """
                SELECT holiday_date
                FROM verigence_attendance.holidays
                WHERE status='ACTIVE'
                  AND holiday_date BETWEEN :start_date AND :end_date
                  AND (
                    work_location_id IS NULL
                    OR work_location_id=:work_location_id
                  )
                """
            ),
            {
                "start_date": start_date,
                "end_date": end_date,
                "work_location_id": employee.get("work_location_id"),
            },
        ).scalars()
    )
    days: list[date] = []
    current = start_date
    while current <= end_date:
        if current.isoweekday() not in weekly_offs and current not in holidays:
            days.append(current)
        current += timedelta(days=1)
    return days


def create_leave_request(
    connection: Connection,
    *,
    employee_id: UUID,
    leave_type_id: UUID,
    start_date: date,
    end_date: date,
    day_mode: str,
    half_day_session: str | None,
    reason: str | None,
) -> dict[str, Any]:
    leave_type = connection.execute(
        text(
            """
            SELECT leave_type_id,leave_name,status,allow_half_day,
                   min_notice_days,max_consecutive_days,requires_reason
            FROM verigence_attendance.leave_types
            WHERE leave_type_id=:leave_type_id
            """
        ),
        {"leave_type_id": leave_type_id},
    ).mappings().first()
    if leave_type is None or leave_type["status"] != "ACTIVE":
        raise AttendanceRuleError(
            "LEAVE_TYPE_INVALID",
            "Leave type is not active.",
            status_code=400,
        )
    if end_date < start_date:
        raise AttendanceRuleError(
            "LEAVE_DATES_INVALID",
            "Leave end date cannot be before start date.",
            status_code=400,
        )

    normalized_reason = (reason or "").strip() or None
    if bool(leave_type["requires_reason"]) and not normalized_reason:
        raise AttendanceRuleError(
            "LEAVE_REASON_REQUIRED",
            "A reason is required for this leave type.",
            status_code=400,
        )

    current_date = connection.execute(text("SELECT CURRENT_DATE")).scalar_one()
    min_notice = int(leave_type["min_notice_days"] or 0)
    if (start_date - current_date).days < min_notice:
        raise AttendanceRuleError(
            "LEAVE_NOTICE_INSUFFICIENT",
            f"This leave type requires at least {min_notice} day(s) notice.",
            status_code=400,
        )

    scheduled_days = _leave_scheduled_days(
        connection,
        employee_id=employee_id,
        start_date=start_date,
        end_date=end_date,
    )
    if not scheduled_days:
        raise AttendanceRuleError(
            "LEAVE_NO_WORKING_DAYS",
            "The selected dates contain no working days after weekly offs and holidays.",
            status_code=400,
        )

    normalized_mode = day_mode.strip().upper()
    normalized_session = (
        half_day_session.strip().upper()
        if half_day_session
        else None
    )
    if normalized_mode == "HALF_DAY":
        if not bool(leave_type["allow_half_day"]):
            raise AttendanceRuleError(
                "LEAVE_HALF_DAY_NOT_ALLOWED",
                "Half-day leave is not allowed for this leave type.",
                status_code=400,
            )
        if start_date != end_date or len(scheduled_days) != 1:
            raise AttendanceRuleError(
                "LEAVE_HALF_DAY_SINGLE_DATE_REQUIRED",
                "Half-day leave must be for one working date.",
                status_code=400,
            )
        if normalized_session not in {"FIRST_HALF", "SECOND_HALF"}:
            raise AttendanceRuleError(
                "LEAVE_HALF_DAY_SESSION_REQUIRED",
                "Choose first half or second half.",
                status_code=400,
            )
        requested_days = Decimal("0.5")
    else:
        normalized_mode = "FULL_DAY"
        normalized_session = None
        requested_days = Decimal(len(scheduled_days))

    max_days = leave_type["max_consecutive_days"]
    if max_days is not None and requested_days > Decimal(str(max_days)):
        raise AttendanceRuleError(
            "LEAVE_MAX_DURATION_EXCEEDED",
            f"This leave type allows a maximum of {max_days} day(s) per request.",
            status_code=400,
        )

    overlap = connection.execute(
        text(
            """
            SELECT 1 FROM verigence_attendance.leave_requests
            WHERE employee_id=:employee_id
              AND status IN ('PENDING_OPERATIONAL','PENDING_HR','APPROVED')
              AND daterange(start_date,end_date,'[]')
                  && daterange(:start_date,:end_date,'[]')
            LIMIT 1
            """
        ),
        {
            "employee_id": employee_id,
            "start_date": start_date,
            "end_date": end_date,
        },
    ).scalar_one_or_none()
    if overlap is not None:
        raise AttendanceRuleError(
            "LEAVE_OVERLAP",
            "A leave request already overlaps these dates.",
        )

    leave_id = uuid4()
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.leave_requests (
                leave_request_id,employee_id,leave_type_id,start_date,end_date,
                requested_days,calculated_days,day_mode,half_day_session,reason
            ) VALUES (
                :leave_id,:employee_id,:leave_type_id,:start_date,:end_date,
                :requested_days,:requested_days,:day_mode,:half_day_session,:reason
            )
            """
        ),
        {
            "leave_id": leave_id,
            "employee_id": employee_id,
            "leave_type_id": leave_type_id,
            "start_date": start_date,
            "end_date": end_date,
            "requested_days": requested_days,
            "day_mode": normalized_mode,
            "half_day_session": normalized_session,
            "reason": normalized_reason,
        },
    )
    return leave_request(connection, leave_id)

def leave_request(connection: Connection, leave_id: UUID) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT l.*,e.display_name,lt.leave_name
            FROM verigence_attendance.leave_requests l
            JOIN verigence_attendance.employees e ON e.employee_id=l.employee_id
            JOIN verigence_attendance.leave_types lt ON lt.leave_type_id=l.leave_type_id
            WHERE l.leave_request_id=:leave_id
            """
        ),
        {"leave_id": leave_id},
    ).mappings().first()
    if row is None:
        raise AttendanceNotFoundError("Leave request not found.")
    result = dict(row)
    result["reviews"] = [
        dict(review)
        for review in connection.execute(
            text(
                """
                SELECT stage,decision,approved_days,actor_role,comment,decided_at_utc
                FROM verigence_attendance.leave_review_actions
                WHERE leave_request_id=:leave_id
                ORDER BY decided_at_utc
                """
            ),
            {"leave_id": leave_id},
        ).mappings()
    ]
    return result


def list_leave_for_employee(
    connection: Connection,
    employee_id: UUID,
) -> list[dict[str, Any]]:
    leave_ids = connection.execute(
        text(
            """
            SELECT leave_request_id
            FROM verigence_attendance.leave_requests
            WHERE employee_id=:employee_id
            ORDER BY created_at_utc DESC
            """
        ),
        {"employee_id": employee_id},
    ).scalars()
    return [
        leave_request(connection, UUID(str(leave_id)))
        for leave_id in leave_ids
    ]


def list_team_attendance(
    connection: Connection,
    *,
    actor_user_id: str,
    attendance_date: date,
) -> list[dict[str, Any]]:
    """Read one day's attendance for employees explicitly assigned to TL/PMO."""
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT e.employee_id,e.display_name,a.attendance_date,a.status,
                       a.present_fraction,a.check_in_at_utc,a.check_out_at_utc,
                       a.hr_review_status
                FROM verigence_attendance.employees e
                LEFT JOIN verigence_attendance.attendance_days a
                  ON a.employee_id=e.employee_id
                 AND a.attendance_date=:attendance_date
                WHERE e.employment_status='ACTIVE'
                  AND (
                    e.tl_user_id=CAST(:actor AS uuid)
                    OR e.pmo_user_id=CAST(:actor AS uuid)
                  )
                ORDER BY lower(e.display_name),e.employee_id
                """
            ),
            {"actor": actor_user_id, "attendance_date": attendance_date},
        ).mappings()
    ]


def list_team_leave(connection: Connection, actor_user_id: str) -> list[dict[str, Any]]:
    leave_ids = connection.execute(
        text(
            """
            SELECT l.leave_request_id
            FROM verigence_attendance.leave_requests l
            JOIN verigence_attendance.employees e ON e.employee_id=l.employee_id
            WHERE l.status='PENDING_OPERATIONAL'
              AND (
                e.tl_user_id=CAST(:actor AS uuid)
                OR e.pmo_user_id=CAST(:actor AS uuid)
              )
            ORDER BY l.created_at_utc
            """
        ),
        {"actor": actor_user_id},
    ).scalars()
    return [
        leave_request(connection, UUID(str(leave_id)))
        for leave_id in leave_ids
    ]


def decide_team_leave(
    connection: Connection,
    *,
    leave_id: UUID,
    actor_user_id: str,
    decision: str,
    comment: str | None,
) -> dict[str, Any]:
    row = leave_request(connection, leave_id)
    employee = employee_by_id(connection, UUID(str(row["employee_id"])))
    if actor_user_id not in {
        str(employee["tl_user_id"]) if employee["tl_user_id"] else "",
        str(employee["pmo_user_id"]) if employee["pmo_user_id"] else "",
    }:
        raise AttendanceRuleError("TEAM_SCOPE_DENIED", "Leave request is outside your assigned team.", status_code=403)
    if row["status"] != "PENDING_OPERATIONAL":
        raise AttendanceRuleError("LEAVE_STATE_INVALID", "Leave request is not awaiting TL/PMO action.")
    normalized_comment = (comment or "").strip() or None
    if decision == "REJECT" and not normalized_comment:
        raise AttendanceRuleError(
            "LEAVE_REJECTION_REASON_REQUIRED",
            "A reason is required when rejecting a leave request.",
            status_code=400,
        )
    next_status = "PENDING_HR" if decision == "APPROVE" else "REJECTED"
    connection.execute(
        text(
            """
            UPDATE verigence_attendance.leave_requests
            SET status=:status,updated_at_utc=now()
            WHERE leave_request_id=:leave_id
            """
        ),
        {"status": next_status, "leave_id": leave_id},
    )
    role = "TL" if str(employee.get("tl_user_id") or "") == actor_user_id else "PMO"
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.approval_actions (
                entity_type,entity_id,stage,decision,actor_user_id,actor_role,comment
            ) VALUES ('LEAVE',:leave_id,'TL_OR_PMO',:decision,CAST(:actor AS uuid),:role,:comment)
            """
        ),
        {
            "leave_id": leave_id,
            "decision": decision,
            "actor": actor_user_id,
            "role": role,
            "comment": normalized_comment,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.leave_review_actions (
                leave_request_id,stage,decision,approved_days,
                actor_user_id,actor_role,comment
            ) VALUES (
                :leave_id,'TL_OR_PMO',:decision,NULL,
                CAST(:actor AS uuid),:role,:comment
            )
            """
        ),
        {
            "leave_id": leave_id,
            "decision": decision,
            "actor": actor_user_id,
            "role": role,
            "comment": normalized_comment,
        },
    )
    return leave_request(connection, leave_id)


def decide_hr_leave(
    connection: Connection,
    *,
    leave_id: UUID,
    actor_user_id: str,
    decision: str,
    approved_days: Decimal | None,
    comment: str | None,
) -> dict[str, Any]:
    row = leave_request(connection, leave_id)
    if row["status"] != "PENDING_HR":
        raise AttendanceRuleError(
            "LEAVE_STATE_INVALID",
            "Leave request is not awaiting HR validation.",
        )

    requested = Decimal(str(row["requested_days"]))
    normalized_comment = (comment or "").strip() or None
    if decision == "APPROVE":
        credited_days = requested
        outcome = "APPROVED"
    elif decision == "ADJUST":
        if approved_days is None or approved_days <= 0 or approved_days >= requested:
            raise AttendanceRuleError(
                "LEAVE_ADJUSTMENT_INVALID",
                "Adjusted approved days must be greater than zero and lower than requested days.",
                status_code=400,
            )
        if not normalized_comment:
            raise AttendanceRuleError(
                "LEAVE_ADJUSTMENT_REASON_REQUIRED",
                "HR must provide a reason when adjusting leave days.",
                status_code=400,
            )
        credited_days = approved_days
        outcome = "ADJUSTED"
    else:
        if not normalized_comment:
            raise AttendanceRuleError(
                "LEAVE_REJECTION_REASON_REQUIRED",
                "HR must provide a reason when rejecting leave.",
                status_code=400,
            )
        credited_days = Decimal(0)
        outcome = "REJECTED"

    next_status = "REJECTED" if credited_days <= 0 else "APPROVED"
    if credited_days > 0:
        balance = connection.execute(
            text(
                """
                SELECT lt.is_paid,lt.allow_negative_balance,
                       COALESCE(lb.opening_days,0)
                       + COALESCE(lb.entitled_days,lt.default_entitlement_days)
                       + COALESCE(lb.adjustment_days,0)
                       - COALESCE(lb.used_days,0) AS available_days
                FROM verigence_attendance.leave_types lt
                LEFT JOIN verigence_attendance.leave_balances lb
                  ON lb.leave_type_id=lt.leave_type_id
                 AND lb.employee_id=:employee_id
                 AND lb.leave_year=:leave_year
                WHERE lt.leave_type_id=:leave_type_id
                """
            ),
            {
                "employee_id": row["employee_id"],
                "leave_year": row["start_date"].year,
                "leave_type_id": row["leave_type_id"],
            },
        ).mappings().one()
        if (
            bool(balance["is_paid"])
            and not bool(balance["allow_negative_balance"])
            and Decimal(str(balance["available_days"])) < credited_days
        ):
            raise AttendanceRuleError(
                "LEAVE_BALANCE_INSUFFICIENT",
                "Insufficient leave balance for the approved leave days.",
                status_code=409,
            )
        if bool(balance["is_paid"]):
            connection.execute(
                text(
                    """
                    INSERT INTO verigence_attendance.leave_balances (
                        employee_id,leave_type_id,leave_year,opening_days,
                        entitled_days,adjustment_days,used_days,updated_at_utc
                    )
                    SELECT :employee_id,lt.leave_type_id,:leave_year,0,
                           lt.default_entitlement_days,0,:used_days,now()
                    FROM verigence_attendance.leave_types lt
                    WHERE lt.leave_type_id=:leave_type_id
                    ON CONFLICT (employee_id,leave_type_id,leave_year) DO UPDATE SET
                        used_days=verigence_attendance.leave_balances.used_days
                                  + EXCLUDED.used_days,
                        updated_at_utc=now()
                    """
                ),
                {
                    "employee_id": row["employee_id"],
                    "leave_type_id": row["leave_type_id"],
                    "leave_year": row["start_date"].year,
                    "used_days": credited_days,
                },
            )

    connection.execute(
        text(
            """
            UPDATE verigence_attendance.leave_requests
            SET status=:status,
                hr_approved_days=:approved_days,
                approval_outcome=:outcome,
                updated_at_utc=now()
            WHERE leave_request_id=:leave_id
            """
        ),
        {
            "status": next_status,
            "approved_days": credited_days,
            "outcome": outcome,
            "leave_id": leave_id,
        },
    )
    aggregate_decision = "REJECT" if credited_days <= 0 else "APPROVE"
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.approval_actions (
                entity_type,entity_id,stage,decision,actor_user_id,actor_role,comment
            ) VALUES (
                'LEAVE',:leave_id,'HR',:decision,
                CAST(:actor AS uuid),'HRADMIN',:comment
            )
            """
        ),
        {
            "leave_id": leave_id,
            "decision": aggregate_decision,
            "actor": actor_user_id,
            "comment": normalized_comment,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.leave_review_actions (
                leave_request_id,stage,decision,approved_days,
                actor_user_id,actor_role,comment
            ) VALUES (
                :leave_id,'HR',:decision,:approved_days,
                CAST(:actor AS uuid),'HRADMIN',:comment
            )
            """
        ),
        {
            "leave_id": leave_id,
            "decision": decision,
            "approved_days": credited_days,
            "actor": actor_user_id,
            "comment": normalized_comment,
        },
    )
    return leave_request(connection, leave_id)

def reimbursement_threshold(connection: Connection) -> Decimal:
    value = connection.execute(
        text(
            """
            SELECT config_value_json
            FROM verigence_attendance.module_configuration
            WHERE config_key='reimbursement.finance_threshold_inr'
            """
        )
    ).scalar_one_or_none()
    return Decimal(str(value if value is not None else 3000))


def month_claim_total(
    connection: Connection,
    *,
    employee_id: UUID,
    expense_date: date,
) -> Decimal:
    value = connection.execute(
        text(
            """
            SELECT COALESCE(sum(amount),0)
            FROM verigence_attendance.reimbursement_claims
            WHERE employee_id=:employee_id
              AND date_trunc('month',expense_date)=date_trunc('month',CAST(:expense_date AS date))
              AND status NOT IN ('REJECTED','CANCELLED')
            """
        ),
        {"employee_id": employee_id, "expense_date": expense_date},
    ).scalar_one()
    return Decimal(str(value))


def create_reimbursement(
    connection: Connection,
    *,
    employee_id: UUID,
    expense_date: date,
    category: str,
    amount: Decimal,
    description: str | None,
    receipt_object_key: str | None,
    receipt_sha256: str | None,
    finance_required: bool,
) -> dict[str, Any]:
    claim_id = uuid4()
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.reimbursement_claims (
                claim_id,employee_id,expense_date,category,amount,description,
                receipt_object_key,receipt_sha256,finance_approval_required
            ) VALUES (
                :claim_id,:employee_id,:expense_date,:category,:amount,:description,
                :receipt_key,:receipt_sha256,:finance_required
            )
            """
        ),
        {
            "claim_id": claim_id,
            "employee_id": employee_id,
            "expense_date": expense_date,
            "category": category,
            "amount": amount,
            "description": description,
            "receipt_key": receipt_object_key,
            "receipt_sha256": receipt_sha256,
            "finance_required": finance_required,
        },
    )
    return reimbursement(connection, claim_id)



def create_reimbursement_claim(
    connection: Connection,
    *,
    employee_id: UUID,
    purpose: str,
    claim_month: date,
    items: list[dict[str, Any]],
    finance_required: bool,
) -> dict[str, Any]:
    if not items:
        raise AttendanceRuleError(
            "REIMBURSEMENT_LINES_REQUIRED",
            "At least one expense line is required.",
            status_code=400,
        )
    claim_id = uuid4()
    claim_number = f"EXP-{claim_month:%Y%m}-{claim_id.hex[:8].upper()}"
    claimed_total = sum(
        (Decimal(str(item["claimed_amount"])) for item in items),
        Decimal(0),
    )
    first_date = min(item["expense_date"] for item in items)
    categories = {str(item["category"]) for item in items}
    legacy_category = (
        next(iter(categories))
        if len(categories) == 1 and next(iter(categories)) in {"TRAVEL", "FOOD", "OTHER"}
        else "OTHER"
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.reimbursement_claims (
                claim_id,employee_id,expense_date,category,amount,description,
                finance_approval_required,claim_number,purpose,claim_month,
                claimed_total,adjusted_total,submitted_at_utc
            ) VALUES (
                :claim_id,:employee_id,:expense_date,:category,:amount,:purpose,
                :finance_required,:claim_number,:purpose,:claim_month,
                :claimed_total,0,now()
            )
            """
        ),
        {
            "claim_id": claim_id,
            "employee_id": employee_id,
            "expense_date": first_date,
            "category": legacy_category,
            "amount": claimed_total,
            "purpose": purpose.strip(),
            "finance_required": finance_required,
            "claim_number": claim_number,
            "claim_month": claim_month,
            "claimed_total": claimed_total,
        },
    )
    for line_number, item in enumerate(items, start=1):
        connection.execute(
            text(
                """
                INSERT INTO verigence_attendance.reimbursement_items (
                    claim_id,line_number,expense_date,category,claimed_amount,
                    vendor_name,description,receipt_object_key,receipt_sha256,
                    travel_from,travel_to,transport_mode,distance_km,
                    ticket_reference,meal_type
                ) VALUES (
                    :claim_id,:line_number,:expense_date,:category,:claimed_amount,
                    :vendor_name,:description,:receipt_object_key,:receipt_sha256,
                    :travel_from,:travel_to,:transport_mode,:distance_km,
                    :ticket_reference,:meal_type
                )
                """
            ),
            {
                "claim_id": claim_id,
                "line_number": line_number,
                **item,
            },
        )
    return reimbursement_claim_detail(connection, claim_id)


def reimbursement_claim_detail(
    connection: Connection,
    claim_id: UUID,
) -> dict[str, Any]:
    header = connection.execute(
        text(
            """
            SELECT c.*,e.display_name
            FROM verigence_attendance.reimbursement_claims c
            JOIN verigence_attendance.employees e ON e.employee_id=c.employee_id
            WHERE c.claim_id=:claim_id
            """
        ),
        {"claim_id": claim_id},
    ).mappings().first()
    if header is None:
        raise AttendanceNotFoundError("Reimbursement claim not found.")
    result = dict(header)
    lines: list[dict[str, Any]] = []
    for row in connection.execute(
        text(
            """
            SELECT *
            FROM verigence_attendance.reimbursement_items
            WHERE claim_id=:claim_id
            ORDER BY line_number
            """
        ),
        {"claim_id": claim_id},
    ).mappings():
        item = dict(row)
        item["reviews"] = [
            dict(review)
            for review in connection.execute(
                text(
                    """
                    SELECT stage,decision,previous_amount,approved_amount,
                           actor_role,comment,decided_at_utc
                    FROM verigence_attendance.reimbursement_item_reviews
                    WHERE reimbursement_item_id=:item_id
                    ORDER BY decided_at_utc
                    """
                ),
                {"item_id": item["reimbursement_item_id"]},
            ).mappings()
        ]
        lines.append(item)
    result["lines"] = lines
    return result


def list_reimbursement_claims_for_employee(
    connection: Connection,
    employee_id: UUID,
) -> list[dict[str, Any]]:
    claim_ids = connection.execute(
        text(
            """
            SELECT claim_id
            FROM verigence_attendance.reimbursement_claims
            WHERE employee_id=:employee_id
            ORDER BY created_at_utc DESC
            """
        ),
        {"employee_id": employee_id},
    ).scalars()
    return [reimbursement_claim_detail(connection, UUID(str(claim_id))) for claim_id in claim_ids]


def list_reimbursement_claims_by_status(
    connection: Connection,
    status: str,
) -> list[dict[str, Any]]:
    claim_ids = connection.execute(
        text(
            """
            SELECT claim_id
            FROM verigence_attendance.reimbursement_claims
            WHERE status=:status
            ORDER BY created_at_utc
            """
        ),
        {"status": status},
    ).scalars()
    return [reimbursement_claim_detail(connection, UUID(str(claim_id))) for claim_id in claim_ids]


def list_pm_team_reimbursement_claims(
    connection: Connection,
    actor_user_id: str,
) -> list[dict[str, Any]]:
    claim_ids = connection.execute(
        text(
            """
            SELECT c.claim_id
            FROM verigence_attendance.reimbursement_claims c
            JOIN verigence_attendance.employees e ON e.employee_id=c.employee_id
            WHERE e.employment_status='ACTIVE'
              AND e.pmo_user_id=CAST(:actor AS uuid)
            ORDER BY c.created_at_utc DESC
            """
        ),
        {"actor": actor_user_id},
    ).scalars()
    return [reimbursement_claim_detail(connection, UUID(str(claim_id))) for claim_id in claim_ids]


def review_reimbursement_claim(
    connection: Connection,
    *,
    claim_id: UUID,
    actor_user_id: str,
    actor_role: str,
    stage: str,
    line_decisions: list[dict[str, Any]],
    comment: str | None,
) -> dict[str, Any]:
    claim = reimbursement_claim_detail(connection, claim_id)
    expected = "PENDING_HR" if stage == "HR" else "PENDING_FINANCE"
    if claim["status"] != expected:
        raise AttendanceRuleError(
            "REIMBURSEMENT_STATE_INVALID",
            f"Claim is not awaiting {stage} review.",
            status_code=409,
        )

    lines = {
        UUID(str(item["reimbursement_item_id"])): item
        for item in claim["lines"]
    }
    decisions = {
        UUID(str(item["reimbursement_item_id"])): item
        for item in line_decisions
    }
    if set(lines) != set(decisions):
        raise AttendanceRuleError(
            "REIMBURSEMENT_LINE_REVIEW_INCOMPLETE",
            "Every expense line must be reviewed before the claim can move forward.",
            status_code=400,
        )

    for item_id, line in lines.items():
        decision = decisions[item_id]
        action = str(decision["decision"])
        approved = Decimal(str(decision["approved_amount"]))
        claimed = Decimal(str(line["claimed_amount"]))
        previous = (
            claimed
            if stage == "HR"
            else Decimal(str(line["approved_amount"] or 0))
        )
        line_comment = (decision.get("comment") or "").strip() or None

        if approved < 0 or approved > previous:
            raise AttendanceRuleError(
                "REIMBURSEMENT_APPROVED_AMOUNT_INVALID",
                "Approved amount must be between zero and the amount entering this review stage.",
                status_code=400,
            )
        if action == "APPROVE" and approved != previous:
            raise AttendanceRuleError(
                "REIMBURSEMENT_APPROVE_AMOUNT_MISMATCH",
                "Use Adjust when the approved amount differs from the reviewed amount.",
                status_code=400,
            )
        if action == "ADJUST" and (approved <= 0 or approved >= previous):
            raise AttendanceRuleError(
                "REIMBURSEMENT_ADJUST_AMOUNT_INVALID",
                "Adjusted amount must be greater than zero and lower than the reviewed amount.",
                status_code=400,
            )
        if action == "REJECT" and approved != 0:
            raise AttendanceRuleError(
                "REIMBURSEMENT_REJECT_AMOUNT_INVALID",
                "Rejected expense lines must have zero approved amount.",
                status_code=400,
            )
        if action in {"ADJUST", "REJECT"} and not line_comment:
            raise AttendanceRuleError(
                "REIMBURSEMENT_REVIEW_REASON_REQUIRED",
                "A reason is required when an expense line is adjusted or rejected.",
                status_code=400,
            )

        if approved == 0:
            line_status = "REJECTED"
        elif stage == "HR" and bool(claim["finance_approval_required"]):
            line_status = "PENDING_FINANCE"
        elif approved < claimed:
            line_status = "ADJUSTED"
        else:
            line_status = "APPROVED"

        connection.execute(
            text(
                """
                UPDATE verigence_attendance.reimbursement_items
                SET approved_amount=:approved_amount,
                    line_status=:line_status,
                    updated_at_utc=now()
                WHERE reimbursement_item_id=:item_id
                """
            ),
            {
                "approved_amount": approved,
                "line_status": line_status,
                "item_id": item_id,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO verigence_attendance.reimbursement_item_reviews (
                    reimbursement_item_id,stage,decision,previous_amount,
                    approved_amount,actor_user_id,actor_role,comment
                ) VALUES (
                    :item_id,:stage,:decision,:previous_amount,
                    :approved_amount,CAST(:actor AS uuid),:actor_role,:comment
                )
                """
            ),
            {
                "item_id": item_id,
                "stage": stage,
                "decision": action,
                "previous_amount": previous,
                "approved_amount": approved,
                "actor": actor_user_id,
                "actor_role": actor_role,
                "comment": line_comment,
            },
        )

    totals = connection.execute(
        text(
            """
            SELECT COALESCE(sum(claimed_amount),0) AS claimed,
                   COALESCE(sum(approved_amount),0) AS approved
            FROM verigence_attendance.reimbursement_items
            WHERE claim_id=:claim_id
            """
        ),
        {"claim_id": claim_id},
    ).mappings().one()
    claimed_total = Decimal(str(totals["claimed"]))
    approved_total = Decimal(str(totals["approved"]))
    adjusted_total = claimed_total - approved_total

    needs_finance = bool(claim["finance_approval_required"])
    if stage == "HR" and needs_finance and approved_total > 0:
        next_status = "PENDING_FINANCE"
        outcome = None
        payment_status = None
    elif approved_total <= 0:
        next_status = "REJECTED"
        outcome = "REJECTED"
        payment_status = None
    else:
        next_status = "APPROVED"
        outcome = (
            "PARTIALLY_APPROVED"
            if approved_total < claimed_total
            else "APPROVED"
        )
        payment_status = "PENDING_PAYMENT"

    connection.execute(
        text(
            """
            UPDATE verigence_attendance.reimbursement_claims
            SET status=:status,
                approval_outcome=:outcome,
                claimed_total=:claimed_total,
                approved_total=:approved_total,
                adjusted_total=:adjusted_total,
                payment_status=:payment_status,
                updated_at_utc=now()
            WHERE claim_id=:claim_id
            """
        ),
        {
            "status": next_status,
            "outcome": outcome,
            "claimed_total": claimed_total,
            "approved_total": approved_total,
            "adjusted_total": adjusted_total,
            "payment_status": payment_status,
            "claim_id": claim_id,
        },
    )
    aggregate_decision = "REJECT" if approved_total <= 0 else "APPROVE"
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.approval_actions (
                entity_type,entity_id,stage,decision,actor_user_id,actor_role,comment
            ) VALUES (
                'REIMBURSEMENT',:claim_id,:stage,:decision,
                CAST(:actor AS uuid),:actor_role,:comment
            )
            """
        ),
        {
            "claim_id": claim_id,
            "stage": stage,
            "decision": aggregate_decision,
            "actor": actor_user_id,
            "actor_role": actor_role,
            "comment": comment,
        },
    )
    return reimbursement_claim_detail(connection, claim_id)


def reimbursement(connection: Connection, claim_id: UUID) -> dict[str, Any]:
    row = connection.execute(
        text(
            """
            SELECT c.*,e.display_name
            FROM verigence_attendance.reimbursement_claims c
            JOIN verigence_attendance.employees e ON e.employee_id=c.employee_id
            WHERE c.claim_id=:claim_id
            """
        ),
        {"claim_id": claim_id},
    ).mappings().first()
    if row is None:
        raise AttendanceNotFoundError("Reimbursement claim not found.")
    return dict(row)


def list_reimbursements_for_employee(
    connection: Connection,
    employee_id: UUID,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT c.*,e.display_name
                FROM verigence_attendance.reimbursement_claims c
                JOIN verigence_attendance.employees e ON e.employee_id=c.employee_id
                WHERE c.employee_id=:employee_id
                ORDER BY c.created_at_utc DESC
                """
            ),
            {"employee_id": employee_id},
        ).mappings()
    ]


def list_pm_team_reimbursements(
    connection: Connection,
    actor_user_id: str,
) -> list[dict[str, Any]]:
    """Read-only team claims for employees explicitly assigned to this PM/PMO.

    This intentionally does not grant approval authority. Scope is enforced in SQL,
    so a normal PC/TL cannot enumerate another employee's reimbursement claims.
    """
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT c.*,e.display_name
                FROM verigence_attendance.reimbursement_claims c
                JOIN verigence_attendance.employees e ON e.employee_id=c.employee_id
                WHERE e.employment_status='ACTIVE'
                  AND e.pmo_user_id=CAST(:actor AS uuid)
                ORDER BY c.expense_date DESC,c.created_at_utc DESC
                """
            ),
            {"actor": actor_user_id},
        ).mappings()
    ]


def list_reimbursements_by_status(
    connection: Connection,
    status: str,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT c.*,e.display_name
                FROM verigence_attendance.reimbursement_claims c
                JOIN verigence_attendance.employees e ON e.employee_id=c.employee_id
                WHERE c.status=:status
                ORDER BY c.created_at_utc
                """
            ),
            {"status": status},
        ).mappings()
    ]



def list_reimbursement_claims_by_payment_status(
    connection: Connection,
    payment_status: str,
) -> list[dict[str, Any]]:
    claim_ids = connection.execute(
        text(
            """
            SELECT claim_id
            FROM verigence_attendance.reimbursement_claims
            WHERE payment_status=:payment_status
              AND status='APPROVED'
            ORDER BY updated_at_utc,created_at_utc
            """
        ),
        {"payment_status": payment_status},
    ).scalars()
    return [
        reimbursement_claim_detail(connection, UUID(str(claim_id)))
        for claim_id in claim_ids
    ]


def decide_reimbursement(
    connection: Connection,
    *,
    claim_id: UUID,
    actor_user_id: str,
    actor_role: str,
    stage: str,
    decision: str,
    comment: str | None,
) -> dict[str, Any]:
    row = reimbursement(connection, claim_id)
    expected = "PENDING_HR" if stage == "HR" else "PENDING_FINANCE"
    if row["status"] != expected:
        raise AttendanceRuleError(
            "REIMBURSEMENT_STATE_INVALID",
            f"Claim is not awaiting {stage} approval.",
        )
    if decision == "REJECT":
        next_status = "REJECTED"
    elif stage == "HR" and bool(row["finance_approval_required"]):
        next_status = "PENDING_FINANCE"
    else:
        next_status = "APPROVED"
    connection.execute(
        text(
            """
            UPDATE verigence_attendance.reimbursement_claims
            SET status=:status,
                payment_status=CASE
                  WHEN :status='APPROVED' THEN 'PENDING_PAYMENT'
                  WHEN :status='REJECTED' THEN NULL
                  ELSE payment_status
                END,
                updated_at_utc=now()
            WHERE claim_id=:claim_id
            """
        ),
        {"status": next_status, "claim_id": claim_id},
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.approval_actions (
                entity_type,entity_id,stage,decision,actor_user_id,actor_role,comment
            ) VALUES (
                'REIMBURSEMENT',:claim_id,:stage,:decision,
                CAST(:actor AS uuid),:actor_role,:comment
            )
            """
        ),
        {
            "claim_id": claim_id,
            "stage": stage,
            "decision": decision,
            "actor": actor_user_id,
            "actor_role": actor_role,
            "comment": comment,
        },
    )
    return reimbursement(connection, claim_id)



def update_reimbursement_payment(
    connection: Connection,
    *,
    claim_id: UUID,
    actor_user_id: str,
    paid_amount: Decimal,
    paid_at_utc: datetime,
    payment_mode: str,
    payment_reference: str,
    comment: str | None,
) -> dict[str, Any]:
    row = reimbursement(connection, claim_id)
    if row["status"] != "APPROVED":
        raise AttendanceRuleError(
            "REIMBURSEMENT_NOT_APPROVED",
            "Only a finally approved reimbursement can be processed for payment.",
            status_code=409,
        )
    if row.get("payment_status") != "PENDING_PAYMENT":
        raise AttendanceRuleError(
            "REIMBURSEMENT_PAYMENT_STATE_INVALID",
            "Only a reimbursement in Pending Payment status can be processed.",
            status_code=409,
        )

    normalized_mode = payment_mode.strip()
    normalized_reference = payment_reference.strip()
    normalized_comment = (comment or "").strip() or None

    if paid_amount <= 0:
        raise AttendanceRuleError(
            "REIMBURSEMENT_PROCESSED_AMOUNT_REQUIRED",
            "Processed amount must be greater than zero.",
            status_code=400,
        )
    approved_total = Decimal(
        str(
            row.get("approved_total")
            if row.get("approved_total") is not None
            else row["amount"]
        )
    )
    if paid_amount != approved_total:
        raise AttendanceRuleError(
            "REIMBURSEMENT_PROCESSED_AMOUNT_INVALID",
            "Processed amount must exactly match the final approved reimbursement amount.",
            status_code=400,
        )
    if not normalized_mode or not normalized_reference:
        raise AttendanceRuleError(
            "REIMBURSEMENT_PAYMENT_REFERENCE_REQUIRED",
            "Payment mode and payment reference are required.",
            status_code=400,
        )

    connection.execute(
        text(
            """
            UPDATE verigence_attendance.reimbursement_claims
            SET payment_status='PROCESSED',
                paid_at_utc=:paid_at_utc,
                paid_amount=:paid_amount,
                payment_mode=:payment_mode,
                payment_reference=:payment_reference,
                payment_processed_by_user_id=CAST(:actor AS uuid),
                payment_comment=:comment,
                updated_at_utc=now()
            WHERE claim_id=:claim_id
            """
        ),
        {
            "claim_id": claim_id,
            "paid_at_utc": paid_at_utc,
            "paid_amount": paid_amount,
            "payment_mode": normalized_mode,
            "payment_reference": normalized_reference,
            "actor": actor_user_id,
            "comment": normalized_comment,
        },
    )
    connection.execute(
        text(
            """
            INSERT INTO verigence_attendance.reimbursement_payment_transactions (
                claim_id,transaction_status,amount,payment_mode,
                payment_reference,actor_user_id,comment
            ) VALUES (
                :claim_id,'SUCCESS',:amount,:payment_mode,
                :payment_reference,CAST(:actor AS uuid),:comment
            )
            """
        ),
        {
            "claim_id": claim_id,
            "amount": paid_amount,
            "payment_mode": normalized_mode,
            "payment_reference": normalized_reference,
            "actor": actor_user_id,
            "comment": normalized_comment,
        },
    )
    return reimbursement_claim_detail(connection, claim_id)

def list_payslips(connection: Connection, employee_id: UUID) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT p.payslip_id,p.pdf_object_key,p.generated_at_utc,
                       r.payroll_month,i.net_amount
                FROM verigence_attendance.payslips p
                JOIN verigence_attendance.payroll_items i
                  ON i.payroll_item_id=p.payroll_item_id
                JOIN verigence_attendance.payroll_runs r
                  ON r.payroll_run_id=i.payroll_run_id
                WHERE p.employee_id=:employee_id AND r.status='FINALIZED'
                ORDER BY r.payroll_month DESC
                """
            ),
            {"employee_id": employee_id},
        ).mappings()
    ]



def leave_balances_for_employee(
    connection: Connection,
    *,
    employee_id: UUID,
    leave_year: int,
) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in connection.execute(
            text(
                """
                SELECT lt.leave_type_id,lt.leave_code,lt.leave_name,lt.is_paid,
                       lt.allow_half_day,
                       COALESCE(lb.opening_days,0) AS opening_days,
                       COALESCE(lb.entitled_days,lt.default_entitlement_days) AS entitled_days,
                       COALESCE(lb.adjustment_days,0) AS adjustment_days,
                       COALESCE(lb.used_days,0) AS used_days,
                       (
                         COALESCE(lb.opening_days,0)
                         + COALESCE(lb.entitled_days,lt.default_entitlement_days)
                         + COALESCE(lb.adjustment_days,0)
                         - COALESCE(lb.used_days,0)
                       ) AS available_days
                FROM verigence_attendance.leave_types lt
                LEFT JOIN verigence_attendance.leave_balances lb
                  ON lb.leave_type_id=lt.leave_type_id
                 AND lb.employee_id=:employee_id
                 AND lb.leave_year=:leave_year
                WHERE lt.status='ACTIVE'
                ORDER BY lt.leave_code
                """
            ),
            {"employee_id": employee_id, "leave_year": leave_year},
        ).mappings()
    ]


def list_leave_by_status(
    connection: Connection,
    status: str,
) -> list[dict[str, Any]]:
    leave_ids = connection.execute(
        text(
            """
            SELECT leave_request_id
            FROM verigence_attendance.leave_requests
            WHERE status=:status
            ORDER BY created_at_utc
            """
        ),
        {"status": status},
    ).scalars()
    return [
        leave_request(connection, UUID(str(leave_id)))
        for leave_id in leave_ids
    ]
