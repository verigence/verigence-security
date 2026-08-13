from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


class ModuleCatalogRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def module(self, module_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT module_key,module_name,catalog_version,status,
                       created_at_utc,updated_at_utc
                FROM security.modules
                WHERE module_key=:module_key
                """
            ),
            {"module_key": module_key},
        ).mappings().first()
        return dict(row) if row else None

    def modules(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT module_key,module_name,catalog_version,status,
                           created_at_utc,updated_at_utc
                    FROM security.modules
                    ORDER BY module_key
                    """
                )
            ).mappings()
        ]

    def upsert_module(
        self,
        *,
        module_key: str,
        module_name: str,
        catalog_version: str,
        actor_user_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.modules
                (module_key,module_name,catalog_version,status,created_at_utc,
                 updated_at_utc,updated_by_user_id)
                VALUES (:module_key,:module_name,:catalog_version,'ACTIVE',:now,:now,
                        :actor_user_id)
                ON CONFLICT (module_key) DO UPDATE SET
                    module_name=EXCLUDED.module_name,
                    catalog_version=EXCLUDED.catalog_version,
                    status='ACTIVE',
                    updated_at_utc=EXCLUDED.updated_at_utc,
                    updated_by_user_id=EXCLUDED.updated_by_user_id
                """
            ),
            {
                "module_key": module_key,
                "module_name": module_name,
                "catalog_version": catalog_version,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )

    def upsert_permission(
        self,
        *,
        permission_key: str,
        module_key: str,
        resource_key: str,
        action_key: str,
        display_name: str,
        description: str | None,
        status: str,
        catalog_version: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.permissions
                (permission_key,module_key,resource_key,action_key,description,status,
                 display_name,catalog_version,updated_at_utc)
                VALUES (:permission_key,:module_key,:resource_key,:action_key,:description,
                        :status,:display_name,:catalog_version,:now)
                ON CONFLICT (permission_key) DO UPDATE SET
                    display_name=EXCLUDED.display_name,
                    description=EXCLUDED.description,
                    status=EXCLUDED.status,
                    catalog_version=EXCLUDED.catalog_version,
                    updated_at_utc=EXCLUDED.updated_at_utc
                WHERE security.permissions.module_key=EXCLUDED.module_key
                  AND security.permissions.resource_key=EXCLUDED.resource_key
                  AND security.permissions.action_key=EXCLUDED.action_key
                """
            ),
            {
                "permission_key": permission_key,
                "module_key": module_key,
                "resource_key": resource_key,
                "action_key": action_key,
                "display_name": display_name,
                "description": description,
                "status": status,
                "catalog_version": catalog_version,
                "now": now,
            },
        )

    def permission(self, permission_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT permission_key,module_key,resource_key,action_key,description,status,
                       display_name,catalog_version,updated_at_utc
                FROM security.permissions
                WHERE permission_key=:permission_key
                """
            ),
            {"permission_key": permission_key},
        ).mappings().first()
        return dict(row) if row else None

    def module_permissions(self, module_key: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT permission_key,module_key,resource_key,action_key,description,
                           status,display_name,catalog_version,updated_at_utc
                    FROM security.permissions
                    WHERE module_key=:module_key
                    ORDER BY permission_key
                    """
                ),
                {"module_key": module_key},
            ).mappings()
        ]

    def effective_role_references(self, permission_key: str) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT DISTINCT r.tenant_id,r.role_id,r.role_key,r.role_name
                    FROM security.roles r
                    JOIN security.role_permissions rp
                      ON rp.tenant_id=r.tenant_id AND rp.role_id=r.role_id
                    WHERE r.status='ACTIVE'
                      AND rp.permission_key=:permission_key
                      AND (
                        EXISTS (
                          SELECT 1
                          FROM security.user_role_assignments ura
                          WHERE ura.tenant_id=r.tenant_id
                            AND ura.role_id=r.role_id
                            AND ura.status='ACTIVE'
                            AND (ura.valid_from_utc IS NULL OR ura.valid_from_utc <= now())
                            AND (ura.valid_to_utc IS NULL OR ura.valid_to_utc > now())
                        )
                        OR EXISTS (
                          SELECT 1
                          FROM security.group_role_assignments gra
                          JOIN security.groups g
                            ON g.tenant_id=gra.tenant_id
                           AND g.group_id=gra.group_id
                           AND g.status='ACTIVE'
                          JOIN security.group_memberships gm
                            ON gm.tenant_id=g.tenant_id
                           AND gm.group_id=g.group_id
                           AND gm.status='ACTIVE'
                          WHERE gra.tenant_id=r.tenant_id
                            AND gra.role_id=r.role_id
                            AND gra.status='ACTIVE'
                            AND (gm.valid_from_utc IS NULL OR gm.valid_from_utc <= now())
                            AND (gm.valid_to_utc IS NULL OR gm.valid_to_utc > now())
                        )
                      )
                    ORDER BY r.tenant_id,r.role_key
                    """
                ),
                {"permission_key": permission_key},
            ).mappings()
        ]

    def upsert_template(
        self,
        *,
        module_key: str,
        template_key: str,
        template_name: str,
        description: str | None,
        catalog_version: str,
        status: str,
        now: datetime,
    ) -> str:
        existing = self.s.execute(
            text(
                """
                SELECT template_id
                FROM security.module_role_templates
                WHERE module_key=:module_key AND template_key=:template_key
                FOR UPDATE
                """
            ),
            {"module_key": module_key, "template_key": template_key},
        ).scalar_one_or_none()
        template_id = str(existing) if existing else str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.module_role_templates
                (template_id,module_key,template_key,template_name,description,
                 catalog_version,status,created_at_utc,updated_at_utc)
                VALUES (:template_id,:module_key,:template_key,:template_name,:description,
                        :catalog_version,:status,:now,:now)
                ON CONFLICT (module_key,template_key) DO UPDATE SET
                    template_name=EXCLUDED.template_name,
                    description=EXCLUDED.description,
                    catalog_version=EXCLUDED.catalog_version,
                    status=EXCLUDED.status,
                    updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "template_id": template_id,
                "module_key": module_key,
                "template_key": template_key,
                "template_name": template_name,
                "description": description,
                "catalog_version": catalog_version,
                "status": status,
                "now": now,
            },
        )
        return template_id

    def replace_template_permissions(
        self,
        *,
        template_id: str,
        permission_keys: tuple[str, ...],
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                DELETE FROM security.module_role_template_permissions
                WHERE template_id=:template_id
                """
            ),
            {"template_id": template_id},
        )
        for permission_key in permission_keys:
            self.s.execute(
                text(
                    """
                    INSERT INTO security.module_role_template_permissions
                    (template_id,permission_key,assigned_at_utc)
                    VALUES (:template_id,:permission_key,:now)
                    """
                ),
                {
                    "template_id": template_id,
                    "permission_key": permission_key,
                    "now": now,
                },
            )

    def module_templates(self, module_key: str) -> list[dict[str, Any]]:
        rows = list(
            self.s.execute(
                text(
                    """
                    SELECT t.template_id,t.module_key,t.template_key,t.template_name,
                           t.description,t.catalog_version,t.status,t.created_at_utc,
                           t.updated_at_utc,tp.permission_key
                    FROM security.module_role_templates t
                    LEFT JOIN security.module_role_template_permissions tp
                      ON tp.template_id=t.template_id
                    WHERE t.module_key=:module_key
                    ORDER BY t.template_key,tp.permission_key
                    """
                ),
                {"module_key": module_key},
            ).mappings()
        )
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            template_id = str(row["template_id"])
            item = result.setdefault(
                template_id,
                {
                    "template_id": row["template_id"],
                    "module_key": row["module_key"],
                    "template_key": row["template_key"],
                    "template_name": row["template_name"],
                    "description": row["description"],
                    "catalog_version": row["catalog_version"],
                    "status": row["status"],
                    "created_at_utc": row["created_at_utc"],
                    "updated_at_utc": row["updated_at_utc"],
                    "permission_keys": [],
                },
            )
            if row["permission_key"] is not None:
                item["permission_keys"].append(str(row["permission_key"]))
        return list(result.values())

    def insert_admin_change(
        self,
        *,
        correlation_id: str,
        actor_user_id: str,
        operation_key: str,
        resource_id: str,
        after_state_json: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,actor_user_id,operation_key,
                 resource_type,resource_id,outcome,after_state_json,occurred_at_utc)
                VALUES (:id,:correlation_id,'PLATFORM',:actor_user_id,:operation_key,
                        'MODULE_CATALOG',:resource_id,'SUCCESS',
                        CAST(:after_state_json AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "actor_user_id": actor_user_id,
                "operation_key": operation_key,
                "resource_id": resource_id,
                "after_state_json": after_state_json,
                "now": now,
            },
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
