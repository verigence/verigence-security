from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class V2AuthorizationRepository:
    """Persistence boundary for synchronous Phase-1 human authorization."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def active_service_integration(self, integration_key: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.service_integrations si
                    JOIN security.security_principals p
                      ON p.principal_id=si.principal_id
                    WHERE si.integration_key=:integration_key
                      AND p.actor_type='SERVICE_INTEGRATION'
                      AND p.status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"integration_key": integration_key},
            ).first()
            is not None
        )

    def human_for_user_id(self, user_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,
                       e.status AS identity_status,
                       u.status AS user_status,
                       p.actor_type AS principal_actor_type,
                       p.status AS principal_status
                FROM security.users u
                JOIN security.security_principals p ON p.principal_id=u.user_id
                JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK'
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    def active_permission(self, permission_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT permission_key,module_key,resource_key,action_key,status
                FROM security.permissions
                WHERE permission_key=:permission_key
                  AND status='ACTIVE'
                """
            ),
            {"permission_key": permission_key},
        ).mappings().first()
        return dict(row) if row is not None else None

    def tenant_status(self, tenant_id: str) -> str | None:
        value = self.s.execute(
            text("SELECT status FROM security.tenants WHERE tenant_id=:tenant_id"),
            {"tenant_id": tenant_id},
        ).scalar_one_or_none()
        return str(value) if value is not None else None

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT role_key,scope_type,scope_id
                    FROM security.user_admin_role_assignments
                    WHERE user_id=:user_id
                      AND status='ACTIVE'
                    ORDER BY role_key,scope_type,scope_id NULLS FIRST
                    """
                ),
                {"user_id": user_id},
            ).mappings()
        ]

    def active_module_roles(
        self,
        *,
        user_id: str,
        tenant_id: str,
        module_key: str,
    ) -> list[str]:
        return [
            str(value)
            for value in self.s.execute(
                text(
                    """
                    SELECT a.role_key
                    FROM security.user_module_role_assignments a
                    JOIN security.module_roles r
                      ON r.module_key=a.module_key AND r.role_key=a.role_key
                    WHERE a.user_id=:user_id
                      AND a.tenant_id=:tenant_id
                      AND a.module_key=:module_key
                      AND a.status='ACTIVE'
                      AND r.status='ACTIVE'
                      AND (a.valid_from_utc IS NULL OR a.valid_from_utc<=CURRENT_TIMESTAMP)
                      AND (a.valid_to_utc IS NULL OR a.valid_to_utc>CURRENT_TIMESTAMP)
                    ORDER BY a.role_key
                    """
                ),
                {
                    "user_id": user_id,
                    "tenant_id": tenant_id,
                    "module_key": module_key,
                },
            ).scalars()
        ]

    def module_role_has_permission(
        self,
        *,
        module_key: str,
        role_key: str,
        permission_key: str,
    ) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.module_role_permissions rp
                    JOIN security.permissions p
                      ON p.permission_key=rp.permission_key
                     AND p.status='ACTIVE'
                    WHERE rp.module_key=:module_key
                      AND rp.role_key=:role_key
                      AND rp.permission_key=:permission_key
                      AND rp.status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {
                    "module_key": module_key,
                    "role_key": role_key,
                    "permission_key": permission_key,
                },
            ).first()
            is not None
        )

    def active_operating_role(self, *, user_id: str, tenant_id: str) -> str | None:
        value = self.s.execute(
            text(
                """
                SELECT role_key
                FROM security.user_tenant_operating_roles
                WHERE user_id=:user_id
                  AND tenant_id=:tenant_id
                  AND status='ACTIVE'
                  AND (valid_from_utc IS NULL OR valid_from_utc<=CURRENT_TIMESTAMP)
                  AND (valid_to_utc IS NULL OR valid_to_utc>CURRENT_TIMESTAMP)
                LIMIT 1
                """
            ),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).scalar_one_or_none()
        return str(value) if value is not None else None

    def tenant_role_has_permission(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permission_key: str,
    ) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.tenant_role_permissions rp
                    JOIN security.permissions p
                      ON p.permission_key=rp.permission_key
                     AND p.status='ACTIVE'
                    WHERE rp.tenant_id=:tenant_id
                      AND rp.role_key=:role_key
                      AND rp.permission_key=:permission_key
                    LIMIT 1
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "role_key": role_key,
                    "permission_key": permission_key,
                },
            ).first()
            is not None
        )

    def active_test_identity_for_user(self, user_id: str) -> str | None:
        value = self.s.execute(
            text(
                """
                SELECT tenant_id
                FROM security.phase1_test_identity
                WHERE singleton_id=1
                  AND user_id=:user_id
                  AND status='ACTIVE'
                """
            ),
            {"user_id": user_id},
        ).scalar_one_or_none()
        return str(value) if value is not None else None
