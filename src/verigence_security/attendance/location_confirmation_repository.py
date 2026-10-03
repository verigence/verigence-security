from __future__ import annotations

from datetime import date, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


class AttendanceLocationConfirmationRepository:
    """Persist and read employee declarations separately from GPS/geofence evidence."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def record(
        self,
        *,
        attendance_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        action: str,
        latitude: float,
        longitude: float,
        accuracy_m: float,
        captured_at: datetime,
        display_address: str,
        confirmed: bool,
        remarks: str | None,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO attendance.location_confirmation (
                    attendance_id,tenant_id,user_id,action,
                    latitude,longitude,accuracy_m,captured_at_utc,
                    display_address,employee_confirmed,remarks
                ) VALUES (
                    :attendance_id,:tenant_id,:user_id,:action,
                    :latitude,:longitude,:accuracy_m,:captured_at_utc,
                    :display_address,:employee_confirmed,:remarks
                )
                ON CONFLICT (attendance_id,action) DO NOTHING
                """
            ),
            {
                "attendance_id": attendance_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "action": action,
                "latitude": latitude,
                "longitude": longitude,
                "accuracy_m": accuracy_m,
                "captured_at_utc": captured_at,
                "display_address": display_address,
                "employee_confirmed": confirmed,
                "remarks": remarks,
            },
        )

    def for_tenant_day(
        self,
        *,
        tenant_id: UUID,
        attendance_date: date,
    ) -> dict[UUID, dict[str, dict[str, Any]]]:
        rows = self.s.execute(
            text(
                """
                SELECT lc.attendance_id,lc.action,lc.display_address,
                       lc.employee_confirmed,lc.remarks
                FROM attendance.location_confirmation lc
                JOIN attendance.daily_attendance da
                  ON da.attendance_id=lc.attendance_id
                 AND da.tenant_id=lc.tenant_id
                WHERE lc.tenant_id=:tenant_id
                  AND da.attendance_date=:attendance_date
                ORDER BY lc.created_at_utc
                """
            ),
            {"tenant_id": tenant_id, "attendance_date": attendance_date},
        ).mappings()
        result: dict[UUID, dict[str, dict[str, Any]]] = {}
        for row in rows:
            attendance_id = UUID(str(row["attendance_id"]))
            result.setdefault(attendance_id, {})[str(row["action"])] = {
                "displayAddress": str(row["display_address"]),
                "employeeConfirmed": bool(row["employee_confirmed"]),
                "remarks": str(row["remarks"]) if row["remarks"] is not None else None,
            }
        return result
