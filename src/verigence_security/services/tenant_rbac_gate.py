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
        membership = self.s.execute(
            text(
                """
                SELECT status,valid_from_utc,valid_to_utc
                FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id},
        ).mappings().first()
        if membership is None:
            _deny("TENANT_MEMBERSHIP_REQUIRED")
        if membership["status"] != "ACTIVE":
            _deny("TENANT_MEMBERSHIP_INACTIVE")
        valid_from = membership["valid_from_utc"]
        valid_to = membership["valid_to_utc"]
        if valid_from is not None and valid_from > now:
            _deny("TENANT_MEMBERSHIP_INACTIVE")
        if valid_to is not None and valid_to <= now:
            _deny("TENANT_MEMBERSHIP_INACTIVE")
        roles, permissions = effective_user_permissions(self.s, tenant_id, user_id, now)
        if permission_key not in permissions:
            _deny("PERMISSION_DENIED")
        return roles, permissions
