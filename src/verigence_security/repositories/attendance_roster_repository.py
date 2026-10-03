from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class AttendanceRosterRepository:
    """Read-only Security view used only by the isolated Attendance service."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def active_members(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT
                        u.user_id,
                        u.display_name,
                        u.primary_email,
                        operating.role_key AS operating_role
                    FROM security.tenant_memberships membership
                    JOIN security.users u
                      ON u.user_id=membership.user_id
                     AND u.status='ACTIVE'
                    JOIN security.security_principals principal
                      ON principal.principal_id=u.user_id
                     AND principal.actor_type='USER'
                     AND principal.status='ACTIVE'
                    LEFT JOIN LATERAL (
                        SELECT role.role_key
                        FROM security.user_tenant_operating_roles role
                        WHERE role.user_id=u.user_id
                          AND role.tenant_id=membership.tenant_id
                          AND role.status='ACTIVE'
                          AND (role.valid_from_utc IS NULL OR role.valid_from_utc<=CURRENT_TIMESTAMP)
                          AND (role.valid_to_utc IS NULL OR role.valid_to_utc>CURRENT_TIMESTAMP)
                        LIMIT 1
                    ) operating ON true
                    WHERE membership.tenant_id=:tenant_id
                      AND membership.status='ACTIVE'
                      AND (membership.valid_from_utc IS NULL OR membership.valid_from_utc<=CURRENT_TIMESTAMP)
                      AND (membership.valid_to_utc IS NULL OR membership.valid_to_utc>CURRENT_TIMESTAMP)
                    ORDER BY lower(u.display_name),u.user_id
                    """
                ),
                {"tenant_id": tenant_id},
            ).mappings()
        ]
