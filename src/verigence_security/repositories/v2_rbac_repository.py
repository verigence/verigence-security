from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Any, cast

from sqlalchemy import text
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session


class V2RbacRepository:
    """Persistence for the additive Security v2 RBAC model.

    This repository intentionally does not read or mutate the legacy Tenant-role or
    Group-derived authorization tables.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def role_definition(self, role_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT role_key,role_class,display_name,status
                FROM security.role_definitions
                WHERE role_key=:role_key
                """
            ),
            {"role_key": role_key},
        ).mappings().first()
        return dict(row) if row else None

    def role_definitions(self) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT role_key,role_class,display_name,status
                FROM security.role_definitions
                ORDER BY role_class,role_key
                """
            )
        ).mappings()
        return [dict(row) for row in rows]

    def lock_user(self, user_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT user_id
                    FROM security.users
                    WHERE user_id=:user_id
                    FOR UPDATE
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    def lock_tenant(self, tenant_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT tenant_id
                    FROM security.tenants
                    WHERE tenant_id=:tenant_id
                    FOR UPDATE
                    """
                ),
                {"tenant_id": tenant_id},
            ).first()
            is not None
        )

    def module_exists(self, module_key: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.modules
                    WHERE module_key=:module_key AND status='ACTIVE'
                    """
                ),
                {"module_key": module_key},
            ).first()
            is not None
        )

    def active_permission_keys(self, permission_keys: Iterable[str]) -> set[str]:
        keys = sorted(set(permission_keys))
        if not keys:
            return set()
        rows = self.s.execute(
            text(
                """
                SELECT permission_key
                FROM security.permissions
                WHERE status='ACTIVE' AND permission_key = ANY(:permission_keys)
                """
            ),
            {"permission_keys": keys},
        ).scalars()
        return {str(value) for value in rows}

    def platform_default_permissions(self, role_key: str) -> list[str]:
        rows = self.s.execute(
            text(
                """
                SELECT permission_key
                FROM security.platform_role_permission_defaults
                WHERE role_key=:role_key AND status='ACTIVE'
                ORDER BY permission_key
                """
            ),
            {"role_key": role_key},
        ).scalars()
        return [str(value) for value in rows]

    def tenant_role_permissions(self, tenant_id: str, role_key: str) -> list[str]:
        rows = self.s.execute(
            text(
                """
                SELECT permission_key
                FROM security.tenant_role_permissions
                WHERE tenant_id=:tenant_id AND role_key=:role_key
                ORDER BY permission_key
                """
            ),
            {"tenant_id": tenant_id, "role_key": role_key},
        ).scalars()
        return [str(value) for value in rows]

    def replace_tenant_role_permissions(
        self,
        *,
        tenant_id: str,
        role_key: str,
        permission_keys: Iterable[str],
        actor_user_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                DELETE FROM security.tenant_role_permissions
                WHERE tenant_id=:tenant_id AND role_key=:role_key
                """
            ),
            {"tenant_id": tenant_id, "role_key": role_key},
        )
        for permission_key in sorted(set(permission_keys)):
            self.s.execute(
                text(
                    """
                    INSERT INTO security.tenant_role_permissions
                    (tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
                    VALUES (:tenant_id,:role_key,:permission_key,:actor_user_id,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "role_key": role_key,
                    "permission_key": permission_key,
                    "actor_user_id": actor_user_id,
                    "now": now,
                },
            )

    def active_operating_role(
        self,
        *,
        user_id: str,
        tenant_id: str,
        for_update: bool = False,
    ) -> dict[str, Any] | None:
        lock = " FOR UPDATE" if for_update else ""
        row = self.s.execute(
            text(
                """
                SELECT assignment_id,user_id,tenant_id,role_key,status,
                       valid_from_utc,valid_to_utc,assigned_by_user_id,
                       assigned_at_utc,ended_at_utc
                FROM security.user_tenant_operating_roles
                WHERE user_id=:user_id AND tenant_id=:tenant_id AND status='ACTIVE'
                """
                + lock
            ),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).mappings().first()
        return dict(row) if row else None

    def active_operating_roles_for_user(self, user_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT assignment_id,tenant_id,role_key
                FROM security.user_tenant_operating_roles
                WHERE user_id=:user_id AND status='ACTIVE'
                ORDER BY tenant_id
                """
            ),
            {"user_id": user_id},
        ).mappings()
        return [dict(row) for row in rows]

    def active_pm(self, tenant_id: str, *, exclude_user_id: str | None = None) -> str | None:
        row = self.s.execute(
            text(
                """
                SELECT user_id
                FROM security.user_tenant_operating_roles
                WHERE tenant_id=:tenant_id AND role_key='PM' AND status='ACTIVE'
                  AND (:exclude_user_id IS NULL OR user_id<>CAST(:exclude_user_id AS uuid))
                LIMIT 1
                """
            ),
            {"tenant_id": tenant_id, "exclude_user_id": exclude_user_id},
        ).first()
        return str(row[0]) if row else None

    def end_active_operating_role(
        self,
        *,
        user_id: str,
        tenant_id: str,
        now: datetime,
    ) -> bool:
        result = self.s.execute(
            text(
                """
                UPDATE security.user_tenant_operating_roles
                SET status='ENDED',ended_at_utc=:now,valid_to_utc=COALESCE(valid_to_utc,:now)
                WHERE user_id=:user_id AND tenant_id=:tenant_id AND status='ACTIVE'
                """
            ),
            {"user_id": user_id, "tenant_id": tenant_id, "now": now},
        )
        return bool(cast(CursorResult[Any], result).rowcount)

    def insert_operating_role(
        self,
        *,
        assignment_id: str,
        user_id: str,
        tenant_id: str,
        role_key: str,
        actor_user_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.user_tenant_operating_roles
                (assignment_id,user_id,tenant_id,role_key,status,valid_from_utc,
                 assigned_by_user_id,assigned_at_utc)
                VALUES (:assignment_id,:user_id,:tenant_id,:role_key,'ACTIVE',:now,
                        :actor_user_id,:now)
                """
            ),
            {
                "assignment_id": assignment_id,
                "user_id": user_id,
                "tenant_id": tenant_id,
                "role_key": role_key,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )

    def active_admin_assignments(self, user_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT assignment_id,role_key,scope_type,scope_id
                FROM security.user_admin_role_assignments
                WHERE user_id=:user_id AND status='ACTIVE'
                ORDER BY role_key,scope_id NULLS FIRST
                """
            ),
            {"user_id": user_id},
        ).mappings()
        return [dict(row) for row in rows]

    def active_admin_assignment(
        self,
        *,
        user_id: str,
        role_key: str,
        scope_type: str,
        scope_id: str | None,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT assignment_id,role_key,scope_type,scope_id
                FROM security.user_admin_role_assignments
                WHERE user_id=:user_id AND role_key=:role_key
                  AND scope_type=:scope_type
                  AND scope_id IS NOT DISTINCT FROM :scope_id
                  AND status='ACTIVE'
                """
            ),
            {
                "user_id": user_id,
                "role_key": role_key,
                "scope_type": scope_type,
                "scope_id": scope_id,
            },
        ).mappings().first()
        return dict(row) if row else None

    def active_super_admin_user_id(self) -> str | None:
        row = self.s.execute(
            text(
                """
                SELECT user_id
                FROM security.user_admin_role_assignments
                WHERE role_key='SuperAdmin' AND status='ACTIVE'
                LIMIT 1
                """
            )
        ).first()
        return str(row[0]) if row else None

    def insert_admin_assignment(
        self,
        *,
        assignment_id: str,
        user_id: str,
        role_key: str,
        scope_type: str,
        scope_id: str | None,
        actor_user_id: str | None,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.user_admin_role_assignments
                (assignment_id,user_id,role_key,scope_type,scope_id,status,
                 assigned_by_user_id,assigned_at_utc)
                VALUES (:assignment_id,:user_id,:role_key,:scope_type,:scope_id,'ACTIVE',
                        :actor_user_id,:now)
                """
            ),
            {
                "assignment_id": assignment_id,
                "user_id": user_id,
                "role_key": role_key,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )

    def end_admin_assignment(
        self,
        *,
        user_id: str,
        role_key: str,
        scope_type: str,
        scope_id: str | None,
        now: datetime,
    ) -> bool:
        result = self.s.execute(
            text(
                """
                UPDATE security.user_admin_role_assignments
                SET status='ENDED',ended_at_utc=:now
                WHERE user_id=:user_id AND role_key=:role_key
                  AND scope_type=:scope_type
                  AND scope_id IS NOT DISTINCT FROM :scope_id
                  AND status='ACTIVE'
                """
            ),
            {
                "user_id": user_id,
                "role_key": role_key,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "now": now,
            },
        )
        return bool(cast(CursorResult[Any], result).rowcount)

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
