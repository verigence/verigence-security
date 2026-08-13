from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


class TenantRbacAdminService:
    def __init__(self, session: Session) -> None:
        self.s = session

    def list_groups(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT group_id,tenant_id,group_key,group_name,description,status,
                       created_at_utc,updated_at_utc
                FROM security.groups
                WHERE tenant_id=:tenant_id
                ORDER BY group_key
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings()
        return [dict(row) for row in rows]

    def get_group(self, tenant_id: str, group_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT group_id,tenant_id,group_key,group_name,description,status,
                       created_at_utc,updated_at_utc
                FROM security.groups
                WHERE tenant_id=:tenant_id AND group_id=:group_id
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id},
        ).mappings().first()
        return dict(row) if row else None

    def create_group(
        self,
        *,
        tenant_id: str,
        group_key: str,
        group_name: str,
        description: str | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        group_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.groups
                (group_id,tenant_id,group_key,group_name,description,status,
                 created_by_user_id,created_at_utc,updated_at_utc)
                VALUES (:group_id,:tenant_id,:group_key,:group_name,:description,'ACTIVE',
                        :actor_user_id,:now,:now)
                """
            ),
            {
                "group_id": group_id,
                "tenant_id": tenant_id,
                "group_key": group_key,
                "group_name": group_name,
                "description": description,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.group.create",
            resource_type="GROUP",
            resource_id=group_id,
            now=now,
        )
        self.s.commit()
        group = self.get_group(tenant_id, group_id)
        if group is None:
            raise RuntimeError("Created group could not be reloaded")
        return group

    def update_group(
        self,
        *,
        tenant_id: str,
        group_id: str,
        actor_user_id: str,
        correlation_id: str,
        group_name: str | None = None,
        description: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_group(tenant_id, group_id)
        if current is None:
            return None
        now = datetime.now(UTC)
        affected_users = self._effective_group_users(tenant_id, group_id, now)
        new_name = group_name if group_name is not None else current["group_name"]
        new_description = description if description is not None else current["description"]
        new_status = status if status is not None else current["status"]
        self.s.execute(
            text(
                """
                UPDATE security.groups
                SET group_name=:group_name,description=:description,status=:status,
                    updated_at_utc=:now
                WHERE tenant_id=:tenant_id AND group_id=:group_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "group_id": group_id,
                "group_name": new_name,
                "description": new_description,
                "status": new_status,
                "now": now,
            },
        )
        if str(current["status"]) != str(new_status):
            self._bump_versions(tenant_id, affected_users, now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.group.update",
            resource_type="GROUP",
            resource_id=group_id,
            now=now,
        )
        self.s.commit()
        return self.get_group(tenant_id, group_id)

    def add_group_member(
        self,
        *,
        tenant_id: str,
        group_id: str,
        user_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        if not self._active_group(tenant_id, group_id):
            raise ValueError("Group must be ACTIVE")
        if not self._active_membership(tenant_id, user_id, now):
            raise ValueError("User must have an ACTIVE Tenant membership")
        existing = self.s.execute(
            text(
                """
                SELECT group_membership_id
                FROM security.group_memberships
                WHERE tenant_id=:tenant_id AND group_id=:group_id
                  AND user_id=:user_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id, "user_id": user_id},
        ).first()
        if existing:
            return False
        self.s.execute(
            text(
                """
                INSERT INTO security.group_memberships
                (group_membership_id,tenant_id,group_id,user_id,status,valid_from_utc,
                 added_by_user_id,added_at_utc)
                VALUES (:id,:tenant_id,:group_id,:user_id,'ACTIVE',:now,
                        :actor_user_id,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "tenant_id": tenant_id,
                "group_id": group_id,
                "user_id": user_id,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )
        self._bump_versions(tenant_id, [user_id], now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.group.member.add",
            resource_type="GROUP_MEMBERSHIP",
            resource_id=f"{group_id}:{user_id}",
            now=now,
        )
        self.s.commit()
        return True

    def remove_group_member(
        self,
        *,
        tenant_id: str,
        group_id: str,
        user_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        row = self.s.execute(
            text(
                """
                UPDATE security.group_memberships
                SET status='ENDED',ended_at_utc=:now
                WHERE tenant_id=:tenant_id AND group_id=:group_id
                  AND user_id=:user_id AND status='ACTIVE'
                RETURNING group_membership_id
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id, "user_id": user_id, "now": now},
        ).first()
        if row is None:
            self.s.rollback()
            return False
        self._bump_versions(tenant_id, [user_id], now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.group.member.remove",
            resource_type="GROUP_MEMBERSHIP",
            resource_id=f"{group_id}:{user_id}",
            now=now,
        )
        self.s.commit()
        return True

    def assign_group_role(
        self,
        *,
        tenant_id: str,
        group_id: str,
        role_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        if not self._active_group(tenant_id, group_id):
            raise ValueError("Group must be ACTIVE")
        if not self._active_role(tenant_id, role_id):
            raise ValueError("Role must be ACTIVE")
        existing = self.s.execute(
            text(
                """
                SELECT assignment_id
                FROM security.group_role_assignments
                WHERE tenant_id=:tenant_id AND group_id=:group_id
                  AND role_id=:role_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id, "role_id": role_id},
        ).first()
        if existing:
            return False
        self.s.execute(
            text(
                """
                INSERT INTO security.group_role_assignments
                (assignment_id,tenant_id,group_id,role_id,status,assigned_by_user_id,
                 assigned_at_utc)
                VALUES (:id,:tenant_id,:group_id,:role_id,'ACTIVE',:actor_user_id,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "tenant_id": tenant_id,
                "group_id": group_id,
                "role_id": role_id,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )
        self._bump_versions(
            tenant_id,
            self._effective_group_users(tenant_id, group_id, now),
            now,
        )
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.group.role.assign",
            resource_type="GROUP_ROLE",
            resource_id=f"{group_id}:{role_id}",
            now=now,
        )
        self.s.commit()
        return True

    def remove_group_role(
        self,
        *,
        tenant_id: str,
        group_id: str,
        role_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        affected_users = self._effective_group_users(tenant_id, group_id, now)
        row = self.s.execute(
            text(
                """
                UPDATE security.group_role_assignments
                SET status='ENDED',ended_at_utc=:now
                WHERE tenant_id=:tenant_id AND group_id=:group_id
                  AND role_id=:role_id AND status='ACTIVE'
                RETURNING assignment_id
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id, "role_id": role_id, "now": now},
        ).first()
        if row is None:
            self.s.rollback()
            return False
        self._bump_versions(tenant_id, affected_users, now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.group.role.remove",
            resource_type="GROUP_ROLE",
            resource_id=f"{group_id}:{role_id}",
            now=now,
        )
        self.s.commit()
        return True

    def list_roles(self, tenant_id: str) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT role_id,tenant_id,role_key,role_name,description,status,
                       created_at_utc,updated_at_utc
                FROM security.roles
                WHERE tenant_id=:tenant_id
                ORDER BY role_key
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings()
        return [dict(row) for row in rows]

    def get_role(self, tenant_id: str, role_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT role_id,tenant_id,role_key,role_name,description,status,
                       created_at_utc,updated_at_utc
                FROM security.roles
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id},
        ).mappings().first()
        return dict(row) if row else None

    def create_role(
        self,
        *,
        tenant_id: str,
        role_key: str,
        role_name: str,
        description: str | None,
        permission_keys: tuple[str, ...],
        actor_user_id: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        if role_key.startswith("platform.") or role_key.startswith("tenant."):
            raise ValueError("Reserved role key")
        self._ensure_active_permissions(permission_keys)
        now = datetime.now(UTC)
        role_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.roles
                (role_id,tenant_id,role_key,role_name,description,status,
                 created_at_utc,updated_at_utc)
                VALUES (:role_id,:tenant_id,:role_key,:role_name,:description,
                        'ACTIVE',:now,:now)
                """
            ),
            {
                "role_id": role_id,
                "tenant_id": tenant_id,
                "role_key": role_key,
                "role_name": role_name,
                "description": description,
                "now": now,
            },
        )
        for permission_key in permission_keys:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.role_permissions
                    (tenant_id,role_id,permission_key,assigned_at_utc)
                    VALUES (:tenant_id,:role_id,:permission_key,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "role_id": role_id,
                    "permission_key": permission_key,
                    "now": now,
                },
            )
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.role.create",
            resource_type="ROLE",
            resource_id=role_id,
            now=now,
        )
        self.s.commit()
        role = self.get_role(tenant_id, role_id)
        if role is None:
            raise RuntimeError("Created role could not be reloaded")
        return role

    def update_role(
        self,
        *,
        tenant_id: str,
        role_id: str,
        actor_user_id: str,
        correlation_id: str,
        role_name: str | None = None,
        description: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any] | None:
        current = self.get_role(tenant_id, role_id)
        if current is None:
            return None
        now = datetime.now(UTC)
        affected = self._effective_role_users(tenant_id, role_id, now)
        new_status = status if status is not None else current["status"]
        self.s.execute(
            text(
                """
                UPDATE security.roles
                SET role_name=:role_name,description=:description,status=:status,
                    updated_at_utc=:now
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                """
            ),
            {
                "tenant_id": tenant_id,
                "role_id": role_id,
                "role_name": role_name if role_name is not None else current["role_name"],
                "description": description if description is not None else current["description"],
                "status": new_status,
                "now": now,
            },
        )
        if str(current["status"]) != str(new_status):
            self._bump_versions(tenant_id, affected, now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.role.update",
            resource_type="ROLE",
            resource_id=role_id,
            now=now,
        )
        self.s.commit()
        return self.get_role(tenant_id, role_id)

    def add_role_permission(
        self,
        *,
        tenant_id: str,
        role_id: str,
        permission_key: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        self._ensure_active_permissions((permission_key,))
        now = datetime.now(UTC)
        if not self._active_role(tenant_id, role_id):
            raise ValueError("Role must be ACTIVE")
        exists = self.s.execute(
            text(
                """
                SELECT 1 FROM security.role_permissions
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                  AND permission_key=:permission_key
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id, "permission_key": permission_key},
        ).first()
        if exists:
            return False
        self.s.execute(
            text(
                """
                INSERT INTO security.role_permissions
                (tenant_id,role_id,permission_key,assigned_at_utc)
                VALUES (:tenant_id,:role_id,:permission_key,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "role_id": role_id,
                "permission_key": permission_key,
                "now": now,
            },
        )
        self._bump_versions(tenant_id, self._effective_role_users(tenant_id, role_id, now), now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.role.permission.add",
            resource_type="ROLE_PERMISSION",
            resource_id=f"{role_id}:{permission_key}",
            now=now,
        )
        self.s.commit()
        return True

    def remove_role_permission(
        self,
        *,
        tenant_id: str,
        role_id: str,
        permission_key: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        affected = self._effective_role_users(tenant_id, role_id, now)
        row = self.s.execute(
            text(
                """
                DELETE FROM security.role_permissions
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                  AND permission_key=:permission_key
                RETURNING permission_key
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id, "permission_key": permission_key},
        ).first()
        if row is None:
            self.s.rollback()
            return False
        self._bump_versions(tenant_id, affected, now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.role.permission.remove",
            resource_type="ROLE_PERMISSION",
            resource_id=f"{role_id}:{permission_key}",
            now=now,
        )
        self.s.commit()
        return True

    def assign_user_role(
        self,
        *,
        tenant_id: str,
        user_id: str,
        role_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        if not self._active_membership(tenant_id, user_id, now):
            raise ValueError("User must have an ACTIVE Tenant membership")
        if not self._active_role(tenant_id, role_id):
            raise ValueError("Role must be ACTIVE")
        exists = self.s.execute(
            text(
                """
                SELECT assignment_id FROM security.user_role_assignments
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND role_id=:role_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "role_id": role_id},
        ).first()
        if exists:
            return False
        self.s.execute(
            text(
                """
                INSERT INTO security.user_role_assignments
                (assignment_id,tenant_id,user_id,role_id,status,valid_from_utc,
                 assigned_by_user_id,assigned_at_utc)
                VALUES (:id,:tenant_id,:user_id,:role_id,'ACTIVE',:now,
                        :actor_user_id,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "tenant_id": tenant_id,
                "user_id": user_id,
                "role_id": role_id,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )
        self._bump_versions(tenant_id, [user_id], now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.role.user.assign",
            resource_type="USER_ROLE",
            resource_id=f"{user_id}:{role_id}",
            now=now,
        )
        self.s.commit()
        return True

    def remove_user_role(
        self,
        *,
        tenant_id: str,
        user_id: str,
        role_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> bool:
        now = datetime.now(UTC)
        row = self.s.execute(
            text(
                """
                UPDATE security.user_role_assignments
                SET status='ENDED',valid_to_utc=:now
                WHERE tenant_id=:tenant_id AND user_id=:user_id
                  AND role_id=:role_id AND status='ACTIVE'
                RETURNING assignment_id
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "role_id": role_id, "now": now},
        ).first()
        if row is None:
            self.s.rollback()
            return False
        self._bump_versions(tenant_id, [user_id], now)
        self._audit(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            operation_key="security.role.user.remove",
            resource_type="USER_ROLE",
            resource_id=f"{user_id}:{role_id}",
            now=now,
        )
        self.s.commit()
        return True

    def list_permissions(self) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT permission_key,module_key,resource_key,action_key,description,
                       status,display_name,catalog_version
                FROM security.permissions
                WHERE status <> 'RETIRED'
                ORDER BY permission_key
                """
            )
        ).mappings()
        return [dict(row) for row in rows]

    def list_templates(self) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT t.template_id,t.module_key,t.template_key,t.template_name,
                       t.description,t.catalog_version,t.status,tp.permission_key
                FROM security.module_role_templates t
                LEFT JOIN security.module_role_template_permissions tp
                  ON tp.template_id=t.template_id
                WHERE t.status <> 'RETIRED'
                ORDER BY t.module_key,t.template_key,tp.permission_key
                """
            )
        ).mappings()
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            key = str(row["template_id"])
            item = result.setdefault(
                key,
                {
                    "template_id": row["template_id"],
                    "module_key": row["module_key"],
                    "template_key": row["template_key"],
                    "template_name": row["template_name"],
                    "description": row["description"],
                    "catalog_version": row["catalog_version"],
                    "status": row["status"],
                    "permission_keys": [],
                },
            )
            if row["permission_key"] is not None:
                item["permission_keys"].append(str(row["permission_key"]))
        return list(result.values())

    def _active_group(self, tenant_id: str, group_id: str) -> bool:
        return self.s.execute(
            text(
                """
                SELECT 1 FROM security.groups
                WHERE tenant_id=:tenant_id AND group_id=:group_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "group_id": group_id},
        ).first() is not None

    def _active_role(self, tenant_id: str, role_id: str) -> bool:
        return self.s.execute(
            text(
                """
                SELECT 1 FROM security.roles
                WHERE tenant_id=:tenant_id AND role_id=:role_id AND status='ACTIVE'
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id},
        ).first() is not None

    def _active_membership(self, tenant_id: str, user_id: str, now: datetime) -> bool:
        return self.s.execute(
            text(
                """
                SELECT 1 FROM security.tenant_memberships
                WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='ACTIVE'
                  AND (valid_from_utc IS NULL OR valid_from_utc<=:now)
                  AND (valid_to_utc IS NULL OR valid_to_utc>:now)
                """
            ),
            {"tenant_id": tenant_id, "user_id": user_id, "now": now},
        ).first() is not None

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
                JOIN security.tenant_memberships tm
                  ON tm.tenant_id=gm.tenant_id AND tm.user_id=gm.user_id
                 AND tm.status='ACTIVE'
                WHERE gm.tenant_id=:tenant_id AND gm.group_id=:group_id
                  AND gm.status='ACTIVE'
                  AND (gm.valid_from_utc IS NULL OR gm.valid_from_utc<=:now)
                  AND (gm.valid_to_utc IS NULL OR gm.valid_to_utc>:now)
                  AND (tm.valid_from_utc IS NULL OR tm.valid_from_utc<=:now)
                  AND (tm.valid_to_utc IS NULL OR tm.valid_to_utc>:now)
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
                    JOIN security.tenant_memberships tm
                      ON tm.tenant_id=ura.tenant_id AND tm.user_id=ura.user_id
                     AND tm.status='ACTIVE'
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
                    JOIN security.tenant_memberships tm
                      ON tm.tenant_id=gm.tenant_id AND tm.user_id=gm.user_id
                     AND tm.status='ACTIVE'
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

    def _ensure_active_permissions(self, permission_keys: tuple[str, ...]) -> None:
        if not permission_keys:
            return
        for permission_key in permission_keys:
            row = self.s.execute(
                text(
                    """
                    SELECT status FROM security.permissions
                    WHERE permission_key=:permission_key
                    """
                ),
                {"permission_key": permission_key},
            ).first()
            if row is None or row[0] != "ACTIVE":
                raise ValueError(f"Permission is not ACTIVE: {permission_key}")

    def _bump_versions(self, tenant_id: str, user_ids: list[str], now: datetime) -> None:
        for user_id in sorted(set(user_ids)):
            self.s.execute(
                text(
                    """
                    UPDATE security.tenant_memberships
                    SET authorization_version=authorization_version+1,
                        updated_at_utc=:now
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='ACTIVE'
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id, "now": now},
            )

    def _audit(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
        operation_key: str,
        resource_type: str,
        resource_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,occurred_at_utc)
                VALUES (:id,:correlation_id,'TENANT',:tenant_id,:actor_user_id,
                        :operation_key,:resource_type,:resource_id,'SUCCESS',:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "tenant_id": tenant_id,
                "actor_user_id": actor_user_id,
                "operation_key": operation_key,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "now": now,
            },
        )
