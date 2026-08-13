from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class PlatformAdminRepository:
    """Persistence primitives for the platform-level Security control plane."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def admin_count(self) -> int:
        value = self.s.execute(text("SELECT count(*) FROM security.platform_admins")).scalar_one()
        return int(value)

    def admin_by_username(self, username: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT admin_id,username,display_name,password_hash,status,
                       must_change_password,created_at_utc,updated_at_utc,last_login_at_utc
                FROM security.platform_admins
                WHERE username=:username
                """
            ),
            {"username": username},
        ).mappings().first()
        return dict(row) if row else None

    def create_admin(
        self,
        *,
        admin_id: str,
        username: str,
        display_name: str,
        password_hash: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.platform_admins
                (admin_id,username,display_name,password_hash,status,must_change_password,
                 created_at_utc,updated_at_utc)
                VALUES
                (:admin_id,:username,:display_name,:password_hash,'ACTIVE',true,:now,:now)
                """
            ),
            {
                "admin_id": admin_id,
                "username": username,
                "display_name": display_name,
                "password_hash": password_hash,
                "now": now,
            },
        )

    def mark_login(self, *, admin_id: str, now: datetime) -> None:
        self.s.execute(
            text(
                """
                UPDATE security.platform_admins
                SET last_login_at_utc=:now,updated_at_utc=:now
                WHERE admin_id=:admin_id AND status='ACTIVE'
                """
            ),
            {"admin_id": admin_id, "now": now},
        )

    def create_tenant(
        self,
        *,
        tenant_id: str,
        tenant_code: str,
        tenant_name: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,:tenant_name,'CONFIGURING',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "tenant_code": tenant_code,
                "tenant_name": tenant_name,
                "now": now,
            },
        )

    def tenants(self) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc
                FROM security.tenants
                ORDER BY created_at_utc,tenant_code
                """
            )
        ).mappings().all()
        return [dict(row) for row in rows]

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
