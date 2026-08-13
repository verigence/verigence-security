from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class RbacAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def upsert_permission(
        self,
        *,
        permission_key: str,
        module_key: str,
        resource_key: str,
        action_key: str,
        description: str | None,
        status: str,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.permissions
                (permission_key,module_key,resource_key,action_key,description,status)
                VALUES
                (:permission_key,:module_key,:resource_key,:action_key,:description,:status)
                ON CONFLICT (permission_key) DO UPDATE SET
                  module_key=EXCLUDED.module_key,
                  resource_key=EXCLUDED.resource_key,
                  action_key=EXCLUDED.action_key,
                  description=EXCLUDED.description,
                  status=EXCLUDED.status
                """
            ),
            {
                "permission_key": permission_key,
                "module_key": module_key,
                "resource_key": resource_key,
                "action_key": action_key,
                "description": description,
                "status": status,
            },
        )

    def upsert_role(
        self,
        *,
        role_id: str,
        tenant_id: str,
        role_key: str,
        role_name: str,
        description: str | None,
        status: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.roles
                (role_id,tenant_id,role_key,role_name,description,status,
                 created_at_utc,updated_at_utc)
                VALUES
                (:role_id,:tenant_id,:role_key,:role_name,:description,:status,:now,:now)
                ON CONFLICT (tenant_id,role_key) DO UPDATE SET
                  role_name=EXCLUDED.role_name,
                  description=EXCLUDED.description,
                  status=EXCLUDED.status,
                  updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "role_id": role_id,
                "tenant_id": tenant_id,
                "role_key": role_key,
                "role_name": role_name,
                "description": description,
                "status": status,
                "now": now,
            },
        )

    def role(self, *, tenant_id: str, role_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.roles
                WHERE tenant_id=:tenant_id AND role_key=:role_key
                """
            ),
            {"tenant_id": tenant_id, "role_key": role_key},
        ).mappings().first()
        return dict(row) if row else None

    def assign_permission(
        self,
        *,
        tenant_id: str,
        role_id: str,
        permission_key: str,
        assigned_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.role_permissions
                (tenant_id,role_id,permission_key,assigned_at_utc)
                VALUES (:tenant_id,:role_id,:permission_key,:assigned_at)
                ON CONFLICT (tenant_id,role_id,permission_key) DO NOTHING
                """
            ),
            {
                "tenant_id": tenant_id,
                "role_id": role_id,
                "permission_key": permission_key,
                "assigned_at": assigned_at,
            },
        )

    def assign_user_role(
        self,
        *,
        assignment_id: str,
        tenant_id: str,
        user_id: str,
        role_id: str,
        valid_from_utc: datetime | None,
        valid_to_utc: datetime | None,
        status: str,
        assigned_by_user_id: str,
        assigned_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.user_role_assignments
                (assignment_id,tenant_id,user_id,role_id,valid_from_utc,valid_to_utc,
                 status,assigned_by_user_id,assigned_at_utc)
                VALUES
                (:assignment_id,:tenant_id,:user_id,:role_id,:valid_from_utc,
                 :valid_to_utc,:status,:assigned_by_user_id,:assigned_at)
                ON CONFLICT (tenant_id,user_id,role_id) WHERE status='ACTIVE'
                DO NOTHING
                """
            ),
            {
                "assignment_id": assignment_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "role_id": role_id,
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
