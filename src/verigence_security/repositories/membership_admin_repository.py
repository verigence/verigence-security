from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class MembershipAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def user_exists(self, user_id: str) -> bool:
        row = self.s.execute(
            text("SELECT 1 FROM security.users WHERE user_id=:user_id"),
            {"user_id": user_id},
        ).first()
        return row is not None

    def upsert_membership(
        self,
        *,
        membership_id: str,
        tenant_id: str,
        user_id: str,
        employee_code: str | None,
        status: str,
        valid_from_utc: datetime | None,
        valid_to_utc: datetime | None,
        authorization_version: int,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_memberships
                (membership_id,tenant_id,user_id,employee_code,status,valid_from_utc,
                 valid_to_utc,authorization_version,created_at_utc,updated_at_utc)
                VALUES
                (:membership_id,:tenant_id,:user_id,:employee_code,:status,:valid_from_utc,
                 :valid_to_utc,:authorization_version,:now,:now)
                ON CONFLICT (tenant_id,user_id) DO UPDATE SET
                  employee_code=EXCLUDED.employee_code,
                  status=EXCLUDED.status,
                  valid_from_utc=EXCLUDED.valid_from_utc,
                  valid_to_utc=EXCLUDED.valid_to_utc,
                  authorization_version=EXCLUDED.authorization_version,
                  updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "membership_id": membership_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "employee_code": employee_code,
                "status": status,
                "valid_from_utc": valid_from_utc,
                "valid_to_utc": valid_to_utc,
                "authorization_version": authorization_version,
                "now": now,
            },
        )

    def membership(self, *, tenant_id: str, user_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).mappings().first()
        return dict(row) if row else None

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
