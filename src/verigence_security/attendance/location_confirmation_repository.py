from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


class AttendanceLocationConfirmationRepository:
    """Persist the employee declaration separately from GPS/geofence evidence."""

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
