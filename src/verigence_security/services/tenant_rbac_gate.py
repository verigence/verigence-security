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
