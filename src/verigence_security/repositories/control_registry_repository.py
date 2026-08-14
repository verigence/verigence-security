from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


class SecurityControlRegistryRepository:
    """Persistence primitives for the approved Security Control Registry v1.4."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def definitions(self) -> list[dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT *
                FROM security.security_control_definitions
                WHERE status='ACTIVE'
                ORDER BY sort_order,control_key
                """
            )
        ).mappings().all()
        return [dict(row) for row in rows]

    def definition(self, control_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.security_control_definitions
                WHERE control_key=:control_key AND status='ACTIVE'
                """
            ),
            {"control_key": control_key},
        ).mappings().first()
        return dict(row) if row else None

    def platform_settings(self) -> dict[str, dict[str, Any]]:
        rows = self.s.execute(
            text("SELECT * FROM security.platform_security_control_settings")
        ).mappings().all()
        return {str(row["control_key"]): dict(row) for row in rows}

    def platform_setting(self, control_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.platform_security_control_settings
                WHERE control_key=:control_key
                """
            ),
            {"control_key": control_key},
        ).mappings().first()
        return dict(row) if row else None

    def tenant_overrides(self, tenant_id: str) -> dict[str, dict[str, Any]]:
        rows = self.s.execute(
            text(
                """
                SELECT * FROM security.tenant_security_control_overrides
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().all()
        return {str(row["control_key"]): dict(row) for row in rows}

    def tenant_override(self, tenant_id: str, control_key: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.tenant_security_control_overrides
                WHERE tenant_id=:tenant_id AND control_key=:control_key
                """
            ),
            {"tenant_id": tenant_id, "control_key": control_key},
        ).mappings().first()
        return dict(row) if row else None

    def tenant_exists(self, tenant_id: str) -> bool:
        return (
            self.s.execute(
                text("SELECT 1 FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).first()
            is not None
        )

    def upsert_platform_setting(
        self,
        *,
        control_key: str,
        enabled: bool,
        configuration_version: int,
        actor_user_id: str,
        updated_at: datetime,
        change_reason: str,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.platform_security_control_settings
                (control_key,enabled,configuration_version,updated_by_user_id,
                 updated_at_utc,change_reason)
                VALUES (:control_key,:enabled,:configuration_version,:actor_user_id,
                        :updated_at,:change_reason)
                ON CONFLICT (control_key) DO UPDATE SET
                  enabled=EXCLUDED.enabled,
                  configuration_version=EXCLUDED.configuration_version,
                  updated_by_user_id=EXCLUDED.updated_by_user_id,
                  updated_at_utc=EXCLUDED.updated_at_utc,
                  change_reason=EXCLUDED.change_reason
                """
            ),
            {
                "control_key": control_key,
                "enabled": enabled,
                "configuration_version": configuration_version,
                "actor_user_id": actor_user_id,
                "updated_at": updated_at,
                "change_reason": change_reason,
            },
        )

    def upsert_tenant_override(
        self,
        *,
        tenant_id: str,
        control_key: str,
        override_mode: str,
        configuration_version: int,
        actor_user_id: str,
        updated_at: datetime,
        change_reason: str,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_security_control_overrides
                (tenant_id,control_key,override_mode,configuration_version,
                 updated_by_user_id,updated_at_utc,change_reason)
                VALUES (:tenant_id,:control_key,:override_mode,:configuration_version,
                        :actor_user_id,:updated_at,:change_reason)
                ON CONFLICT (tenant_id,control_key) DO UPDATE SET
                  override_mode=EXCLUDED.override_mode,
                  configuration_version=EXCLUDED.configuration_version,
                  updated_by_user_id=EXCLUDED.updated_by_user_id,
                  updated_at_utc=EXCLUDED.updated_at_utc,
                  change_reason=EXCLUDED.change_reason
                """
            ),
            {
                "tenant_id": tenant_id,
                "control_key": control_key,
                "override_mode": override_mode,
                "configuration_version": configuration_version,
                "actor_user_id": actor_user_id,
                "updated_at": updated_at,
                "change_reason": change_reason,
            },
        )

    def audit(
        self,
        *,
        correlation_id: str,
        actor_user_id: str,
        operation_key: str,
        resource_type: str,
        resource_id: str,
        occurred_at: datetime,
        before_state: dict[str, Any] | None,
        after_state: dict[str, Any] | None,
        tenant_id: str | None = None,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,before_state_json,
                 after_state_json,occurred_at_utc)
                VALUES (:id,:correlation_id,:scope_type,:tenant_id,:actor_user_id,
                        :operation_key,:resource_type,:resource_id,'SUCCESS',
                        CAST(:before_state AS jsonb),CAST(:after_state AS jsonb),:occurred_at)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "scope_type": "TENANT" if tenant_id is not None else "PLATFORM",
                "tenant_id": tenant_id,
                "actor_user_id": actor_user_id,
                "operation_key": operation_key,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "before_state": json.dumps(before_state, default=str) if before_state is not None else None,
                "after_state": json.dumps(after_state, default=str) if after_state is not None else None,
                "occurred_at": occurred_at,
            },
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
