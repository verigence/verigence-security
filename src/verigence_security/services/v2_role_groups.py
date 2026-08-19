from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.services.v2_rbac import OPERATING_ROLE_KEYS


class RoleAlignedGroupService:
    """Read-only Phase-1 Groups projected from active operating-role assignments.

    Groups are presentation only. They do not read legacy group_memberships,
    group_role_assignments, or any Group-specific permission source.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def tenant_exists(self, tenant_id: str) -> bool:
        return (
            self.s.execute(
                text("SELECT 1 FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).first()
            is not None
        )

    def list_groups(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT rd.role_key,rd.display_name,COUNT(utor.assignment_id) AS member_count
                FROM security.role_definitions rd
                LEFT JOIN security.user_tenant_operating_roles utor
                  ON utor.tenant_id=:tenant_id
                 AND utor.role_key=rd.role_key
                 AND utor.status='ACTIVE'
                WHERE rd.role_class='OPERATING'
                  AND rd.status='ACTIVE'
                GROUP BY rd.role_key,rd.display_name
                ORDER BY CASE rd.role_key
                  WHEN 'PC' THEN 1
                  WHEN 'TL' THEN 2
                  WHEN 'PM' THEN 3
                  WHEN 'CRM' THEN 4
                  WHEN 'Executive' THEN 5
                  ELSE 99
                END,rd.role_key
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings()
        return [dict(row) for row in rows if str(row["role_key"]) in OPERATING_ROLE_KEYS]

    def group(self, tenant_id: str, role_key: str) -> dict[str, Any] | None:
        if role_key not in OPERATING_ROLE_KEYS:
            return None
        row = self.s.execute(
            text(
                """
                SELECT rd.role_key,rd.display_name,COUNT(utor.assignment_id) AS member_count
                FROM security.role_definitions rd
                LEFT JOIN security.user_tenant_operating_roles utor
                  ON utor.tenant_id=:tenant_id
                 AND utor.role_key=rd.role_key
                 AND utor.status='ACTIVE'
                WHERE rd.role_key=:role_key
                  AND rd.role_class='OPERATING'
                  AND rd.status='ACTIVE'
                GROUP BY rd.role_key,rd.display_name
                """
            ),
            {"tenant_id": tenant_id, "role_key": role_key},
        ).mappings().first()
        return dict(row) if row is not None else None

    def users(self, tenant_id: str, role_key: str) -> list[dict[str, Any]]:
        if role_key not in OPERATING_ROLE_KEYS:
            return []
        rows = self.s.execute(
            text(
                """
                SELECT u.user_id,u.display_name,u.primary_email,u.status
                FROM security.user_tenant_operating_roles utor
                JOIN security.users u ON u.user_id=utor.user_id
                WHERE utor.tenant_id=:tenant_id
                  AND utor.role_key=:role_key
                  AND utor.status='ACTIVE'
                ORDER BY lower(u.display_name),u.user_id
                """
            ),
            {"tenant_id": tenant_id, "role_key": role_key},
        ).mappings()
        return [dict(row) for row in rows]
