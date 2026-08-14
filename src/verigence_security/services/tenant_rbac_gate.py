from __future__ import annotations

from datetime import UTC, datetime
from typing import NoReturn

from sqlalchemy import text

from verigence_security.core.errors import ERRORS, SecurityError
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.tenant_rbac_admin import TenantRbacAdminService


def _deny(code: str) -> NoReturn:
    status_code, title = ERRORS[code]
    raise SecurityError(code=code, status_code=status_code, title=title)


class TenantRbacGateService(TenantRbacAdminService):
    """v1.4.2 Tenant RBAC using a global USER registry and Tenant-scoped assignments."""

    def authorize_user(
        self,
        *,
        tenant_id: str,
        user_id: str,
        permission_key: str,
    ) -> tuple[list[str], list[str]]:
        now = datetime.now(UTC)
        state = self.s.execute(
            text(
                """
                SELECT t.status AS tenant_status,u.status AS user_status,
                       p.status AS principal_status
                FROM security.users u
                JOIN security.security_principals p ON p.principal_id=u.user_id
                CROSS JOIN security.tenants t
                WHERE u.user_id=:user_id AND t.tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).mappings().first()
        if state is None or state["tenant_status"] != "ACTIVE":
            _deny("TENANT_NOT_ACTIVE")
        if state["principal_status"] != "ACTIVE":
            _deny("PRINCIPAL_NOT_ACTIVE")
        if state["user_status"] != "ACTIVE":
            _deny("USER_NOT_ACTIVE")

        # Tenant access is established by effective Tenant-scoped authorization only. No
        # tenant_memberships row is required in v1.4.2.
        roles, permissions = effective_user_permissions(self.s, tenant_id, user_id, now)
        if permission_key not in permissions:
            _deny("PERMISSION_DENIED")
        return roles, permissions

    # The inherited v1.4 RBAC administration methods intentionally call these helper methods.
    # Overriding them removes the membership prerequisite without duplicating the entire
    # administration implementation.
    def _active_membership(self, tenant_id: str, user_id: str, now: datetime) -> bool:
        _ = tenant_id, now
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.users u
                    JOIN security.security_principals p ON p.principal_id=u.user_id
                    WHERE u.user_id=:user_id
                      AND u.status='ACTIVE'
                      AND p.status='ACTIVE'
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    def _bump_versions(self, tenant_id: str, user_ids: list[str], now: datetime) -> None:
        for user_id in sorted(set(user_ids)):
            self.s.execute(
                text(
                    """
                    INSERT INTO security.user_tenant_authorization_state
                    (user_id,tenant_id,authorization_version,updated_at_utc)
                    VALUES (:user_id,:tenant_id,2,:now)
                    ON CONFLICT (user_id,tenant_id) DO UPDATE SET
                      authorization_version=
                        security.user_tenant_authorization_state.authorization_version+1,
                      updated_at_utc=EXCLUDED.updated_at_utc
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id, "now": now},
            )

    def _effective_group_users(
        self,
        tenant_id: str,
        group_id: str,
        now: datetime,
    ) -> list[str]:
        rows = self.s.execute(
            text(
                """
                SELECT gm.user_id
                FROM security.group_memberships gm
                JOIN security.users u ON u.user_id=gm.user_id AND u.status='ACTIVE'
                JOIN security.security_principals p
                  ON p.principal_id=gm.user_id AND p.status='ACTIVE'
                WHERE gm.tenant_id=:tenant_id AND gm.group_id=:group_id
                  AND gm.status='ACTIVE'
                  AND (gm.valid_from_utc IS NULL OR gm.valid_from_utc<=:now)
                  AND (gm.valid_to_utc IS NULL OR gm.valid_to_utc>:now)
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id, "now": now},
        ).scalars()
        return [str(value) for value in rows]

    def _effective_role_users(
        self,
        tenant_id: str,
        role_id: str,
        now: datetime,
    ) -> list[str]:
        rows = self.s.execute(
            text(
                """
                SELECT DISTINCT user_id
                FROM (
                    SELECT ura.user_id
                    FROM security.user_role_assignments ura
                    JOIN security.users u ON u.user_id=ura.user_id AND u.status='ACTIVE'
                    JOIN security.security_principals p
                      ON p.principal_id=ura.user_id AND p.status='ACTIVE'
                    WHERE ura.tenant_id=:tenant_id AND ura.role_id=:role_id
                      AND ura.status='ACTIVE'
                      AND (ura.valid_from_utc IS NULL OR ura.valid_from_utc<=:now)
                      AND (ura.valid_to_utc IS NULL OR ura.valid_to_utc>:now)
                    UNION
                    SELECT gm.user_id
                    FROM security.group_role_assignments gra
                    JOIN security.groups g
                      ON g.tenant_id=gra.tenant_id AND g.group_id=gra.group_id
                     AND g.status='ACTIVE'
                    JOIN security.group_memberships gm
                      ON gm.tenant_id=g.tenant_id AND gm.group_id=g.group_id
                     AND gm.status='ACTIVE'
                    JOIN security.users u ON u.user_id=gm.user_id AND u.status='ACTIVE'
                    JOIN security.security_principals p
                      ON p.principal_id=gm.user_id AND p.status='ACTIVE'
                    WHERE gra.tenant_id=:tenant_id AND gra.role_id=:role_id
                      AND gra.status='ACTIVE'
                      AND (gm.valid_from_utc IS NULL OR gm.valid_from_utc<=:now)
                      AND (gm.valid_to_utc IS NULL OR gm.valid_to_utc>:now)
                ) effective_users
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id, "now": now},
        ).scalars()
        return [str(value) for value in rows]
