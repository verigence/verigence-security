from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, time
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4
from zoneinfo import ZoneInfo

from sqlalchemy import Connection

from verigence_security.attendance.employee.domain import (
    GeoPoint,
    distance_meters,
    finance_approval_required,
)
from verigence_security.attendance.employee.errors import AttendanceRuleError
from verigence_security.attendance.employee.repository import (
    attendance_rule_config,
    create_reimbursement,
    create_reimbursement_claim,
    employee_for_user,
    insert_attendance_event,
    insert_attendance_flag,
    lock_attendance_day,
    month_claim_total,
    reimbursement_threshold,
    update_attendance_day,
)
from verigence_security.attendance.employee.settings import get_settings
from verigence_security.attendance.employee.storage import (
    AttendanceStorage,
    AttendanceStorageError,
)

_ALLOWED_PHOTO_TYPES = {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
_ALLOWED_RECEIPT_TYPES = _ALLOWED_PHOTO_TYPES | {"application/pdf"}
_MAX_PHOTO_BYTES = 10 * 1024 * 1024
_MAX_RECEIPT_BYTES = 15 * 1024 * 1024
_MAX_CAPTURE_AGE_SECONDS = 120


def _fresh_capture(captured_at: datetime) -> datetime:
    if captured_at.tzinfo is None:
        raise AttendanceRuleError(
            "CAPTURE_TIME_INVALID",
            "Capture timestamp must include timezone information.",
            status_code=400,
        )
    normalized = captured_at.astimezone(UTC)
    age = abs((datetime.now(UTC) - normalized).total_seconds())
    if age > _MAX_CAPTURE_AGE_SECONDS:
        raise AttendanceRuleError(
            "CAPTURE_NOT_FRESH",
            "Attendance evidence must be captured live.",
            status_code=400,
        )
    return normalized


def _photo_bytes(data: bytes, content_type: str) -> bytes:
    if content_type not in _ALLOWED_PHOTO_TYPES:
        raise AttendanceRuleError(
            "PHOTO_TYPE_INVALID",
            "Attendance requires a live photo.",
            status_code=400,
        )
    if not data or len(data) > _MAX_PHOTO_BYTES:
        raise AttendanceRuleError(
            "PHOTO_SIZE_INVALID",
            "Attendance photo is empty or too large.",
            status_code=400,
        )
    return data


def _local_rule_time(value: object, default: str) -> time:
    raw = str(value or default)
    try:
        hour, minute = raw.split(":", 1)
        return time(hour=int(hour), minute=int(minute))
    except (ValueError, TypeError) as exc:
        raise AttendanceRuleError(
            "ATTENDANCE_RULE_TIME_INVALID",
            f"Attendance rule time {raw!r} is invalid.",
            status_code=500,
        ) from exc


def record_attendance(
    connection: Connection,
    *,
    user_id: str,
    event_type: str,
    latitude: float,
    longitude: float,
    accuracy_meters: float,
    captured_at: datetime,
    photo_data: bytes,
    photo_content_type: str,
    actor_role: str,
    exception_reason: str | None,
    storage: AttendanceStorage,
) -> dict[str, object]:
    if event_type not in {"CHECK_IN", "CHECK_OUT"}:
        raise ValueError("Unsupported attendance event")
    if accuracy_meters < 0:
        raise AttendanceRuleError(
            "LOCATION_ACCURACY_INVALID",
            "Location accuracy is invalid.",
            status_code=400,
        )

    employee = employee_for_user(connection, user_id)
    rules = attendance_rule_config(connection)
    normalized_role = actor_role.strip().upper()
    pc_geofence_required = bool(rules.get("attendance.pc_geofence_required", True))
    work_location_available = (
        employee.get("work_location_id") is not None
        and employee.get("work_latitude") is not None
        and employee.get("work_longitude") is not None
        and employee.get("work_location_status") == "ACTIVE"
    )

    radius: int | None = None
    distance: float | None = None
    geofence_result = "UNVERIFIABLE"
    if work_location_available:
        radius = int(employee.get("geofence_radius_meters") or 500)
        distance = distance_meters(
            GeoPoint(latitude=latitude, longitude=longitude),
            GeoPoint(
                latitude=float(employee["work_latitude"]),
                longitude=float(employee["work_longitude"]),
            ),
        )
        geofence_result = "WITHIN" if distance <= radius else "OUTSIDE"
    elif normalized_role == "PC" and pc_geofence_required:
        raise AttendanceRuleError(
            "WORK_LOCATION_REQUIRED",
            "An active work location is required for PC attendance.",
            status_code=409,
        )

    normalized_exception = (exception_reason or "").strip() or None
    if (
        normalized_role == "PC"
        and pc_geofence_required
        and geofence_result == "OUTSIDE"
        and not normalized_exception
    ):
        raise AttendanceRuleError(
            "GEOFENCE_EXCEPTION_REASON_REQUIRED",
            "You are outside the work-location geofence. Add a reason to continue.",
            status_code=409,
        )

    evidence_time = _fresh_capture(captured_at)
    photo = _photo_bytes(photo_data, photo_content_type)
    business_date = evidence_time.astimezone(ZoneInfo(get_settings().timezone_iana)).date()
    day = lock_attendance_day(
        connection,
        employee_id=UUID(str(employee["employee_id"])),
        attendance_date=business_date,
    )

    if event_type == "CHECK_IN":
        if day.get("check_in_at_utc") is not None:
            raise AttendanceRuleError("ALREADY_CHECKED_IN", "You are already checked in today.")
    else:
        if day.get("check_in_at_utc") is None:
            raise AttendanceRuleError("CHECK_IN_REQUIRED", "Check in before checking out.")
        if day.get("check_out_at_utc") is not None:
            raise AttendanceRuleError("ALREADY_CHECKED_OUT", "You are already checked out today.")
        if evidence_time <= day["check_in_at_utc"]:
            raise AttendanceRuleError(
                "CHECK_OUT_TIME_INVALID",
                "Check-out time must be after check-in.",
                status_code=400,
            )

    event_id = uuid4()
    extension = {
        "image/jpeg": "jpg",
        "image/png": "png",
        "image/webp": "webp",
        "image/heic": "heic",
        "image/heif": "heif",
    }[photo_content_type]
    object_key = (
        f"employee-attendance/{employee['employee_id']}/{business_date.isoformat()}/"
        f"{event_id}.{extension}"
    )
    digest = hashlib.sha256(photo).hexdigest()
    try:
        storage.put(object_key=object_key, data=photo, content_type=photo_content_type)
    except AttendanceStorageError as exc:
        raise AttendanceRuleError(
            "ATTENDANCE_STORAGE_UNAVAILABLE",
            "Could not store attendance photo. Please retry.",
            status_code=503,
        ) from exc

    insert_attendance_event(
        connection,
        attendance_day_id=UUID(str(day["attendance_day_id"])),
        employee_id=UUID(str(employee["employee_id"])),
        event_id=event_id,
        event_type=event_type,
        captured_at=evidence_time,
        latitude=latitude,
        longitude=longitude,
        accuracy_meters=accuracy_meters,
        work_location_id=(
            UUID(str(employee["work_location_id"]))
            if employee.get("work_location_id") is not None
            else None
        ),
        distance_meters=distance,
        radius_meters=radius,
        geofence_result=geofence_result,
        exception_reason=normalized_exception,
        actor_role=normalized_role,
        photo_object_key=object_key,
        photo_sha256=digest,
    )

    local_time = evidence_time.astimezone(
        ZoneInfo(get_settings().timezone_iana)
    ).time().replace(tzinfo=None)
    late_after = _local_rule_time(
        rules.get("attendance.late_checkin_after_local"),
        "11:00",
    )
    early_before = _local_rule_time(
        rules.get("attendance.early_checkout_before_local"),
        "17:00",
    )
    flag_reasons: list[tuple[str, str, str | None]] = []
    if (
        normalized_role == "PC"
        and pc_geofence_required
        and geofence_result == "OUTSIDE"
    ):
        flag_reasons.append(
            (
                "OUTSIDE_GEOFENCE",
                f"Captured {round(float(distance or 0), 2)}m from a {radius}m geofence.",
                normalized_exception,
            )
        )
    if event_type == "CHECK_IN" and local_time > late_after:
        flag_reasons.append(
            (
                "LATE_CHECK_IN",
                f"Check-in at {local_time.strftime('%H:%M')} after {late_after.strftime('%H:%M')}.",
                None,
            )
        )
    if event_type == "CHECK_OUT" and local_time < early_before:
        flag_reasons.append(
            (
                "EARLY_CHECK_OUT",
                f"Check-out at {local_time.strftime('%H:%M')} before {early_before.strftime('%H:%M')}.",
                None,
            )
        )
    for flag_type, detail, employee_reason in flag_reasons:
        insert_attendance_flag(
            connection,
            attendance_day_id=UUID(str(day["attendance_day_id"])),
            attendance_event_id=event_id,
            employee_id=UUID(str(employee["employee_id"])),
            flag_type=flag_type,
            flag_detail=detail,
            employee_reason=employee_reason,
        )

    update_attendance_day(
        connection,
        attendance_day_id=UUID(str(day["attendance_day_id"])),
        event_type=event_type,
        captured_at=evidence_time,
    )
    return {
        "attendanceEventId": event_id,
        "attendanceDate": business_date,
        "eventType": event_type,
        "capturedAtUtc": evidence_time,
        "distanceMeters": round(distance, 2) if distance is not None else None,
        "geofenceRadiusMeters": radius,
        "geofenceResult": geofence_result,
        "hrReviewRequired": bool(flag_reasons),
    }



def submit_reimbursement_claim(
    connection: Connection,
    *,
    user_id: str,
    purpose: str,
    lines: list[dict[str, Any]],
    receipts: list[tuple[bytes, str | None]],
    storage: AttendanceStorage,
) -> dict[str, object]:
    employee = employee_for_user(connection, user_id)
    normalized_purpose = purpose.strip()
    if not normalized_purpose:
        raise AttendanceRuleError(
            "REIMBURSEMENT_PURPOSE_REQUIRED",
            "Claim purpose is required.",
            status_code=400,
        )
    if not lines or len(lines) > 50:
        raise AttendanceRuleError(
            "REIMBURSEMENT_LINES_INVALID",
            "A claim must contain between 1 and 50 expense lines.",
            status_code=400,
        )

    months = {
        (line["expense_date"].year, line["expense_date"].month)
        for line in lines
        if isinstance(line.get("expense_date"), date)
    }
    if len(months) != 1:
        raise AttendanceRuleError(
            "REIMBURSEMENT_MONTH_MIXED",
            "All expense lines in one claim must belong to the same calendar month.",
            status_code=400,
        )

    receipt_indexes: set[int] = set()
    prepared: list[dict[str, Any]] = []
    claimed_total = Decimal(0)

    for line_number, line in enumerate(lines, start=1):
        category = str(line["category"]).strip().upper()
        amount = Decimal(str(line["claimed_amount"]))
        if amount <= 0:
            raise AttendanceRuleError(
                "REIMBURSEMENT_AMOUNT_INVALID",
                f"Expense line {line_number} amount must be greater than zero.",
                status_code=400,
            )

        travel_from = (str(line.get("travel_from") or "").strip() or None)
        travel_to = (str(line.get("travel_to") or "").strip() or None)
        transport_mode = (str(line.get("transport_mode") or "").strip().upper() or None)
        vendor_name = (str(line.get("vendor_name") or "").strip() or None)
        meal_type = (str(line.get("meal_type") or "").strip().upper() or None)
        description = (str(line.get("description") or "").strip() or None)

        if (
            category in {"TRAVEL", "LOCAL_CONVEYANCE"}
            and (not travel_from or not travel_to or not transport_mode)
        ):
            raise AttendanceRuleError(
                "REIMBURSEMENT_TRAVEL_DETAILS_REQUIRED",
                f"Expense line {line_number} requires From, To and mode of transport.",
                status_code=400,
            )
        if category == "FOOD" and not meal_type:
            raise AttendanceRuleError(
                "REIMBURSEMENT_MEAL_TYPE_REQUIRED",
                f"Expense line {line_number} requires a meal type.",
                status_code=400,
            )
        if category == "LODGING" and not vendor_name:
            raise AttendanceRuleError(
                "REIMBURSEMENT_LODGING_VENDOR_REQUIRED",
                f"Expense line {line_number} requires the hotel/vendor name.",
                status_code=400,
            )

        receipt_key: str | None = None
        receipt_sha: str | None = None
        receipt_index = line.get("receipt_index")
        if receipt_index is not None:
            index = int(receipt_index)
            if index < 0 or index >= len(receipts):
                raise AttendanceRuleError(
                    "REIMBURSEMENT_RECEIPT_INDEX_INVALID",
                    f"Expense line {line_number} references an invalid receipt.",
                    status_code=400,
                )
            if index in receipt_indexes:
                raise AttendanceRuleError(
                    "REIMBURSEMENT_RECEIPT_REUSED",
                    "Each uploaded receipt must belong to only one expense line.",
                    status_code=400,
                )
            receipt_indexes.add(index)
            receipt_data, receipt_type = receipts[index]
            content_type = (receipt_type or "").strip().lower()
            if content_type not in _ALLOWED_RECEIPT_TYPES:
                raise AttendanceRuleError(
                    "RECEIPT_TYPE_INVALID",
                    f"Expense line {line_number} receipt must be a photo or PDF.",
                    status_code=400,
                )
            if not receipt_data or len(receipt_data) > _MAX_RECEIPT_BYTES:
                raise AttendanceRuleError(
                    "RECEIPT_SIZE_INVALID",
                    f"Expense line {line_number} receipt is empty or too large.",
                    status_code=400,
                )
            receipt_id = uuid4()
            extension = (
                "pdf"
                if content_type == "application/pdf"
                else content_type.split("/")[-1]
            )
            receipt_key = (
                f"employee-reimbursement-items/{employee['employee_id']}/"
                f"{line['expense_date'].isoformat()}/{receipt_id}.{extension}"
            )
            receipt_sha = hashlib.sha256(receipt_data).hexdigest()
            try:
                storage.put(
                    object_key=receipt_key,
                    data=receipt_data,
                    content_type=content_type,
                )
            except AttendanceStorageError as exc:
                raise AttendanceRuleError(
                    "REIMBURSEMENT_STORAGE_UNAVAILABLE",
                    "Could not store an expense receipt. Please retry.",
                    status_code=503,
                ) from exc
        elif not description:
            raise AttendanceRuleError(
                "REIMBURSEMENT_EVIDENCE_REQUIRED",
                f"Expense line {line_number} needs either a receipt or a description.",
                status_code=400,
            )

        prepared.append(
            {
                "expense_date": line["expense_date"],
                "category": category,
                "claimed_amount": amount,
                "vendor_name": vendor_name,
                "description": description,
                "receipt_object_key": receipt_key,
                "receipt_sha256": receipt_sha,
                "travel_from": travel_from,
                "travel_to": travel_to,
                "transport_mode": transport_mode,
                "distance_km": line.get("distance_km"),
                "ticket_reference": (
                    str(line.get("ticket_reference") or "").strip() or None
                ),
                "meal_type": meal_type,
            }
        )
        claimed_total += amount

    first_date = min(item["expense_date"] for item in prepared)
    claim_month = first_date.replace(day=1)
    employee_id = UUID(str(employee["employee_id"]))
    month_total = month_claim_total(
        connection,
        employee_id=employee_id,
        expense_date=first_date,
    )
    threshold = reimbursement_threshold(connection)
    needs_finance = finance_approval_required(
        month_total,
        claimed_total,
        threshold,
    )
    return create_reimbursement_claim(
        connection,
        employee_id=employee_id,
        purpose=normalized_purpose,
        claim_month=claim_month,
        items=prepared,
        finance_required=needs_finance,
    )


def submit_reimbursement(
    connection: Connection,
    *,
    user_id: str,
    expense_date: date,
    category: str,
    amount: Decimal,
    description: str | None,
    receipt_data: bytes | None,
    receipt_content_type: str | None,
    storage: AttendanceStorage,
) -> dict[str, object]:
    employee = employee_for_user(connection, user_id)
    normalized_category = category.strip().upper()
    if normalized_category not in {"TRAVEL", "FOOD", "OTHER"}:
        raise AttendanceRuleError(
            "REIMBURSEMENT_CATEGORY_INVALID",
            "Reimbursement category must be Travel, Food or Other.",
            status_code=400,
        )
    if amount <= 0:
        raise AttendanceRuleError(
            "REIMBURSEMENT_AMOUNT_INVALID",
            "Reimbursement amount must be greater than zero.",
            status_code=400,
        )

    receipt_key: str | None = None
    receipt_sha: str | None = None
    if receipt_data is not None:
        content_type = (receipt_content_type or "").strip().lower()
        if content_type not in _ALLOWED_RECEIPT_TYPES:
            raise AttendanceRuleError(
                "RECEIPT_TYPE_INVALID",
                "Receipt must be a photo or PDF.",
                status_code=400,
            )
        if not receipt_data or len(receipt_data) > _MAX_RECEIPT_BYTES:
            raise AttendanceRuleError(
                "RECEIPT_SIZE_INVALID",
                "Receipt is empty or too large.",
                status_code=400,
            )
        receipt_id = uuid4()
        extension = "pdf" if content_type == "application/pdf" else content_type.split("/")[-1]
        receipt_key = (
            f"employee-reimbursements/{employee['employee_id']}/"
            f"{expense_date.isoformat()}/{receipt_id}.{extension}"
        )
        receipt_sha = hashlib.sha256(receipt_data).hexdigest()
        try:
            storage.put(
                object_key=receipt_key,
                data=receipt_data,
                content_type=content_type,
            )
        except AttendanceStorageError as exc:
            raise AttendanceRuleError(
                "REIMBURSEMENT_STORAGE_UNAVAILABLE",
                "Could not store reimbursement receipt. Please retry.",
                status_code=503,
            ) from exc

    employee_id = UUID(str(employee["employee_id"]))
    month_total = month_claim_total(
        connection,
        employee_id=employee_id,
        expense_date=expense_date,
    )
    threshold = reimbursement_threshold(connection)
    needs_finance = finance_approval_required(month_total, amount, threshold)
    return create_reimbursement(
        connection,
        employee_id=employee_id,
        expense_date=expense_date,
        category=normalized_category,
        amount=amount,
        description=description,
        receipt_object_key=receipt_key,
        receipt_sha256=receipt_sha,
        finance_required=needs_finance,
    )
