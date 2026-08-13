from __future__ import annotations

from datetime import datetime, time
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class ScheduleAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def upsert_schedule(
        self,
        *,
        schedule_id: str,
        tenant_id: str,
        schedule_key: str,
        schedule_name: str,
        status: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.access_schedules
                (schedule_id,tenant_id,schedule_key,schedule_name,status,
                 created_at_utc,updated_at_utc)
                VALUES
                (:schedule_id,:tenant_id,:schedule_key,:schedule_name,:status,:now,:now)
                ON CONFLICT (schedule_id) DO UPDATE SET
                  schedule_key=EXCLUDED.schedule_key,
                  schedule_name=EXCLUDED.schedule_name,
                  status=EXCLUDED.status,
                  updated_at_utc=EXCLUDED.updated_at_utc
                WHERE security.access_schedules.tenant_id=EXCLUDED.tenant_id
                """
            ),
            {
                "schedule_id": schedule_id,
                "tenant_id": tenant_id,
                "schedule_key": schedule_key,
                "schedule_name": schedule_name,
                "status": status,
                "now": now,
            },
        )

    def schedule(self, *, tenant_id: str, schedule_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.access_schedules
                WHERE tenant_id=:tenant_id AND schedule_id=:schedule_id
                """
            ),
            {"tenant_id": tenant_id, "schedule_id": schedule_id},
        ).mappings().first()
        return dict(row) if row else None

    def upsert_window(
        self,
        *,
        schedule_window_id: str,
        tenant_id: str,
        schedule_id: str,
        iso_day_of_week: int,
        start_local_time: time,
        end_local_time: time,
        crosses_midnight: bool,
        status: str,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.access_schedule_windows
                (schedule_window_id,tenant_id,schedule_id,iso_day_of_week,
                 start_local_time,end_local_time,crosses_midnight,status)
                VALUES
                (:schedule_window_id,:tenant_id,:schedule_id,:iso_day_of_week,
                 :start_local_time,:end_local_time,:crosses_midnight,:status)
                ON CONFLICT (schedule_window_id) DO UPDATE SET
                  iso_day_of_week=EXCLUDED.iso_day_of_week,
                  start_local_time=EXCLUDED.start_local_time,
                  end_local_time=EXCLUDED.end_local_time,
                  crosses_midnight=EXCLUDED.crosses_midnight,
                  status=EXCLUDED.status
                WHERE security.access_schedule_windows.tenant_id=EXCLUDED.tenant_id
                  AND security.access_schedule_windows.schedule_id=EXCLUDED.schedule_id
                """
            ),
            {
                "schedule_window_id": schedule_window_id,
                "tenant_id": tenant_id,
                "schedule_id": schedule_id,
                "iso_day_of_week": iso_day_of_week,
                "start_local_time": start_local_time,
                "end_local_time": end_local_time,
                "crosses_midnight": crosses_midnight,
                "status": status,
            },
        )

    def windows(self, *, tenant_id: str, schedule_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT * FROM security.access_schedule_windows
                WHERE tenant_id=:tenant_id AND schedule_id=:schedule_id
                ORDER BY iso_day_of_week,start_local_time,schedule_window_id
                """
            ),
            {"tenant_id": tenant_id, "schedule_id": schedule_id},
        ).mappings().all()
        return [dict(row) for row in rows]

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
