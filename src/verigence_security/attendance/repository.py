from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.orm import Session


class AttendanceRepository:
    """Persistence boundary for the isolated Attendance schema only."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def policy(self, tenant_id: UUID) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT tenant_id,timezone_iana,expected_start_local,checkin_reminder_local,
                       expected_end_local,checkout_reminder_local,pc_geofence_radius_m,
                       max_location_accuracy_m,max_location_age_seconds,
                       geofence_exception_allowed
                FROM attendance.policy
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    def upsert_policy(self, *, tenant_id: UUID, updated_by_user_id: UUID, values: dict[str, Any]) -> dict[str, Any]:
        row = self.s.execute(
            text(
                """
                INSERT INTO attendance.policy (
                    tenant_id,timezone_iana,expected_start_local,checkin_reminder_local,
                    expected_end_local,checkout_reminder_local,pc_geofence_radius_m,
                    max_location_accuracy_m,max_location_age_seconds,
                    geofence_exception_allowed,updated_by_user_id
                ) VALUES (
                    :tenant_id,:timezone_iana,:expected_start_local,:checkin_reminder_local,
                    :expected_end_local,:checkout_reminder_local,:pc_geofence_radius_m,
                    :max_location_accuracy_m,:max_location_age_seconds,
                    :geofence_exception_allowed,:updated_by_user_id
                )
                ON CONFLICT (tenant_id) DO UPDATE SET
                    timezone_iana=EXCLUDED.timezone_iana,
                    expected_start_local=EXCLUDED.expected_start_local,
                    checkin_reminder_local=EXCLUDED.checkin_reminder_local,
                    expected_end_local=EXCLUDED.expected_end_local,
                    checkout_reminder_local=EXCLUDED.checkout_reminder_local,
                    pc_geofence_radius_m=EXCLUDED.pc_geofence_radius_m,
                    max_location_accuracy_m=EXCLUDED.max_location_accuracy_m,
                    max_location_age_seconds=EXCLUDED.max_location_age_seconds,
                    geofence_exception_allowed=EXCLUDED.geofence_exception_allowed,
                    updated_by_user_id=EXCLUDED.updated_by_user_id,
                    updated_at_utc=CURRENT_TIMESTAMP
                RETURNING tenant_id,timezone_iana,expected_start_local,checkin_reminder_local,
                          expected_end_local,checkout_reminder_local,pc_geofence_radius_m,
                          max_location_accuracy_m,max_location_age_seconds,
                          geofence_exception_allowed
                """
            ),
            {"tenant_id": tenant_id, "updated_by_user_id": updated_by_user_id, **values},
        ).mappings().one()
        return dict(row)

    def for_date(self, *, tenant_id: UUID, user_id: UUID, attendance_date: date) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM attendance.daily_attendance
                WHERE tenant_id=:tenant_id
                  AND user_id=:user_id
                  AND attendance_date=:attendance_date
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "attendance_date": attendance_date},
        ).mappings().first()
        return dict(row) if row is not None else None

    def by_id(self, *, tenant_id: UUID, attendance_id: UUID) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM attendance.daily_attendance
                WHERE tenant_id=:tenant_id AND attendance_id=:attendance_id
                """
            ),
            {"tenant_id": tenant_id, "attendance_id": attendance_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    def create_check_in(self, values: dict[str, Any]) -> dict[str, Any]:
        row = self.s.execute(
            text(
                """
                INSERT INTO attendance.daily_attendance (
                    tenant_id,user_id,attendance_date,role_key,status,
                    check_in_at_utc,check_in_latitude,check_in_longitude,check_in_accuracy_m,
                    check_in_dealer_id,check_in_outlet_id,check_in_distance_m,
                    check_in_result,check_in_exception_reason
                ) VALUES (
                    :tenant_id,:user_id,:attendance_date,:role_key,:status,
                    :check_in_at_utc,:latitude,:longitude,:accuracy_m,
                    :dealer_id,:outlet_id,:distance_m,:result_code,:exception_reason
                )
                RETURNING *
                """
            ),
            values,
        ).mappings().one()
        return dict(row)

    def check_out(self, values: dict[str, Any]) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                UPDATE attendance.daily_attendance
                SET status=:status,
                    check_out_at_utc=:check_out_at_utc,
                    check_out_latitude=:latitude,
                    check_out_longitude=:longitude,
                    check_out_accuracy_m=:accuracy_m,
                    check_out_dealer_id=:dealer_id,
                    check_out_outlet_id=:outlet_id,
                    check_out_distance_m=:distance_m,
                    check_out_result=:result_code,
                    check_out_exception_reason=:exception_reason,
                    updated_at_utc=CURRENT_TIMESTAMP
                WHERE tenant_id=:tenant_id
                  AND attendance_id=:attendance_id
                  AND check_out_at_utc IS NULL
                RETURNING *
                """
            ),
            values,
        ).mappings().first()
        return dict(row) if row is not None else None

    def append_event(
        self,
        *,
        attendance_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        event_type: str,
        latitude: float | None,
        longitude: float | None,
        accuracy_m: float | None,
        dealer_id: UUID | None,
        outlet_id: UUID | None,
        distance_m: float | None,
        result_code: str | None,
        reason: str | None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO attendance.attendance_event (
                    attendance_id,tenant_id,user_id,event_type,latitude,longitude,
                    accuracy_m,dealer_id,outlet_id,distance_m,result_code,reason,metadata_json
                ) VALUES (
                    :attendance_id,:tenant_id,:user_id,:event_type,:latitude,:longitude,
                    :accuracy_m,:dealer_id,:outlet_id,:distance_m,:result_code,:reason,
                    CAST(:metadata_json AS jsonb)
                )
                """
            ),
            {
                "attendance_id": attendance_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "event_type": event_type,
                "latitude": latitude,
                "longitude": longitude,
                "accuracy_m": accuracy_m,
                "dealer_id": dealer_id,
                "outlet_id": outlet_id,
                "distance_m": distance_m,
                "result_code": result_code,
                "reason": reason,
                "metadata_json": json.dumps(metadata or {}),
            },
        )

    def history(self, *, tenant_id: UUID, user_id: UUID, limit: int) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT *
                    FROM attendance.daily_attendance
                    WHERE tenant_id=:tenant_id AND user_id=:user_id
                    ORDER BY attendance_date DESC,check_in_at_utc DESC
                    LIMIT :limit
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id, "limit": limit},
            ).mappings()
        ]

    def tenant_day(self, *, tenant_id: UUID, attendance_date: date, limit: int = 1000) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT *
                    FROM attendance.daily_attendance
                    WHERE tenant_id=:tenant_id AND attendance_date=:attendance_date
                    ORDER BY check_in_at_utc,user_id
                    LIMIT :limit
                    """
                ),
                {"tenant_id": tenant_id, "attendance_date": attendance_date, "limit": limit},
            ).mappings()
        ]

    def correct(
        self,
        *,
        tenant_id: UUID,
        attendance_id: UUID,
        corrected_by_user_id: UUID,
        check_in_at: datetime | None,
        check_out_at: datetime | None,
        reason: str,
    ) -> dict[str, Any] | None:
        before = self.by_id(tenant_id=tenant_id, attendance_id=attendance_id)
        if before is None:
            return None

        row = self.s.execute(
            text(
                """
                UPDATE attendance.daily_attendance
                SET check_in_at_utc=COALESCE(:check_in_at,check_in_at_utc),
                    check_out_at_utc=COALESCE(:check_out_at,check_out_at_utc),
                    status='CORRECTED',
                    corrected_by_user_id=:corrected_by_user_id,
                    correction_reason=:reason,
                    updated_at_utc=CURRENT_TIMESTAMP
                WHERE tenant_id=:tenant_id AND attendance_id=:attendance_id
                RETURNING *
                """
            ),
            {
                "tenant_id": tenant_id,
                "attendance_id": attendance_id,
                "corrected_by_user_id": corrected_by_user_id,
                "check_in_at": check_in_at,
                "check_out_at": check_out_at,
                "reason": reason,
            },
        ).mappings().first()
        if row is None:
            return None
        after = dict(row)
        self.s.execute(
            text(
                """
                INSERT INTO attendance.correction (
                    attendance_id,tenant_id,user_id,corrected_by_user_id,reason,
                    before_json,after_json
                ) VALUES (
                    :attendance_id,:tenant_id,:user_id,:corrected_by_user_id,:reason,
                    CAST(:before_json AS jsonb),CAST(:after_json AS jsonb)
                )
                """
            ),
            {
                "attendance_id": attendance_id,
                "tenant_id": tenant_id,
                "user_id": after["user_id"],
                "corrected_by_user_id": corrected_by_user_id,
                "reason": reason,
                "before_json": json.dumps(before, default=str),
                "after_json": json.dumps(after, default=str),
            },
        )
        return after
