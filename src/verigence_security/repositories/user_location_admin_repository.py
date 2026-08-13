from __future__ import annotations

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session


class UserLocationAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

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

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
