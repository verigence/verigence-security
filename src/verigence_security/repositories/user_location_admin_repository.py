from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class UserLocationAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def list_assignments(self, *, tenant_id: str, user_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT ula.*,l.location_code,l.location_name,
                       s.schedule_key,s.schedule_name
                FROM security.user_location_assignments ula
                JOIN security.tenant_locations l
                  ON l.tenant_id=ula.tenant_id AND l.location_id=ula.location_id
                JOIN security.access_schedules s
                  ON s.tenant_id=ula.tenant_id AND s.schedule_id=ula.schedule_id
                WHERE ula.tenant_id=:tenant_id AND ula.user_id=:user_id
                ORDER BY ula.assigned_at_utc DESC,ula.assignment_id
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).mappings().all()
        return [dict(row) for row in rows]

    def assignment(
        self,
        *,
        tenant_id: str,
        user_id: str,
        assignment_id: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.user_location_assignments
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND assignment_id=:assignment_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "assignment_id": assignment_id,
            },
        ).mappings().first()
        return dict(row) if row else None

    def assign(
        self,
        *,
        assignment_id: str,
        tenant_id: str,
        user_id: str,
        location_id: str,
        schedule_id: str,
        valid_from_utc: datetime | None,
        valid_to_utc: datetime | None,
        status: str,
        assigned_by_user_id: str,
        assigned_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.user_location_assignments
                (assignment_id,tenant_id,user_id,location_id,schedule_id,valid_from_utc,
                 valid_to_utc,status,assigned_by_user_id,assigned_at_utc)
                VALUES
                (:assignment_id,:tenant_id,:user_id,:location_id,:schedule_id,
                 :valid_from_utc,:valid_to_utc,:status,:assigned_by_user_id,:assigned_at)
                ON CONFLICT (tenant_id,user_id,location_id) WHERE status='ACTIVE'
                DO NOTHING
                """
            ),
            {
                "assignment_id": assignment_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "location_id": location_id,
                "schedule_id": schedule_id,
                "valid_from_utc": valid_from_utc,
                "valid_to_utc": valid_to_utc,
                "status": status,
                "assigned_by_user_id": assigned_by_user_id,
                "assigned_at": assigned_at,
            },
        )

    def end_assignment(
        self,
        *,
        tenant_id: str,
        user_id: str,
        assignment_id: str,
        ended_at: datetime,
    ) -> bool:
        row = self.s.execute(
            text(
                """
                UPDATE security.user_location_assignments
                SET status='ENDED',valid_to_utc=COALESCE(valid_to_utc,:ended_at)
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND assignment_id=:assignment_id AND status='ACTIVE'
                RETURNING assignment_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "assignment_id": assignment_id,
                "ended_at": ended_at,
            },
        ).first()
        return row is not None

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
