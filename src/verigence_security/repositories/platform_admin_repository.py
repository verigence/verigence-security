from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session


class PlatformAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def active_super_admin_exists(self) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.platform_user_role_assignments
                    WHERE role_key='platform.super_admin' AND status='ACTIVE'
                    LIMIT 1
                    """
                )
            ).first()
            is not None
        )

    def create_bootstrap_super_admin(
        self,
        *,
        login_name: str,
        password_hash: str,
        now: datetime,
    ) -> str:
        user_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER',:login_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "login_name": login_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,:login_name,'ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "login_name": login_name, "now": now},
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.local_user_credentials
                (credential_id,user_id,login_name,password_hash,status,
                 must_change_password,created_at_utc,updated_at_utc)
                VALUES (:credential_id,:user_id,:login_name,:password_hash,'ACTIVE',
                        true,:now,:now)
                """
            ),
            {
                "credential_id": str(uuid4()),
                "user_id": user_id,
                "login_name": login_name,
                "password_hash": password_hash,
                "now": now,
            },
        )
        self.s.execute(
            text(
                """
                INSERT INTO security.platform_user_role_assignments
                (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
                VALUES (:assignment_id,:user_id,'platform.super_admin','ACTIVE',
                        'BOOTSTRAP',:now)
                """
            ),
            {"assignment_id": str(uuid4()), "user_id": user_id, "now": now},
        )
        return user_id

    def local_credential_by_login(self, login_name: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT c.user_id,c.login_name,c.password_hash,c.status AS credential_status,
                       c.must_change_password,p.status AS principal_status,
                       u.status AS user_status
                FROM security.local_user_credentials c
                JOIN security.security_principals p ON p.principal_id=c.user_id
                JOIN security.users u ON u.user_id=c.user_id
                WHERE c.login_name=:login_name
                """
            ),
            {"login_name": login_name},
        ).mappings().first()
        return dict(row) if row else None

    def platform_roles_permissions(self, user_id: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
        rows = list(
            self.s.execute(
                text(
                    """
                    SELECT DISTINCT a.role_key,rp.permission_key
                    FROM security.platform_user_role_assignments a
                    JOIN security.platform_roles r
                      ON r.role_key=a.role_key AND r.status='ACTIVE'
                    JOIN security.platform_role_permissions rp ON rp.role_key=r.role_key
                    JOIN security.permissions p
                      ON p.permission_key=rp.permission_key AND p.status='ACTIVE'
                    WHERE a.user_id=:user_id AND a.status='ACTIVE'
                    ORDER BY a.role_key,rp.permission_key
                    """
                ),
                {"user_id": user_id},
            ).mappings()
        )
        roles = tuple(sorted({str(row["role_key"]) for row in rows}))
        permissions = tuple(sorted({str(row["permission_key"]) for row in rows}))
        return roles, permissions

    def credential_state_for_user(self, user_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT user_id,login_name,password_hash,status,must_change_password
                FROM security.local_user_credentials
                WHERE user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row else None

    def change_password(self, *, user_id: str, password_hash: str, now: datetime) -> bool:
        row = self.s.execute(
            text(
                """
                UPDATE security.local_user_credentials
                SET password_hash=:password_hash,
                    must_change_password=false,
                    password_changed_at_utc=:now,
                    updated_at_utc=:now
                WHERE user_id=:user_id AND status='ACTIVE'
                RETURNING user_id
                """
            ),
            {"user_id": user_id, "password_hash": password_hash, "now": now},
        ).first()
        return row is not None

    def insert_admin_change(
        self,
        *,
        correlation_id: str,
        actor_user_id: str,
        operation_key: str,
        resource_type: str,
        resource_id: str | None,
        outcome: str,
        now: datetime,
        tenant_id: str | None = None,
        before_state_json: str | None = None,
        after_state_json: str | None = None,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,before_state_json,
                 after_state_json,occurred_at_utc)
                VALUES
                (:admin_change_id,:correlation_id,:scope_type,:tenant_id,:actor_user_id,
                 :operation_key,:resource_type,:resource_id,:outcome,
                 CAST(:before_state_json AS jsonb),CAST(:after_state_json AS jsonb),:now)
                """
            ),
            {
                "admin_change_id": str(uuid4()),
                "correlation_id": correlation_id,
                "scope_type": "TENANT" if tenant_id else "PLATFORM",
                "tenant_id": tenant_id,
                "actor_user_id": actor_user_id,
                "operation_key": operation_key,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "outcome": outcome,
                "before_state_json": before_state_json,
                "after_state_json": after_state_json,
                "now": now,
            },
        )

    def acquire_tenant_create_idempotency_lock(
        self,
        *,
        actor_user_id: str,
        idempotency_key: str,
    ) -> None:
        self.s.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:lock_key))"),
            {
                "lock_key": (
                    f"security.platform.tenant.create:{actor_user_id}:{idempotency_key}"
                )
            },
        )

    def tenant_create_receipt(
        self,
        *,
        actor_user_id: str,
        idempotency_key: str,
    ) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT resource_id,
                       after_state_json->>'tenantName' AS tenant_name
                FROM security.admin_change_records
                WHERE actor_user_id=:actor_user_id
                  AND operation_key='platform.tenant.create'
                  AND outcome='SUCCESS'
                  AND after_state_json->>'idempotencyKey'=:idempotency_key
                ORDER BY occurred_at_utc DESC
                LIMIT 1
                """
            ),
            {
                "actor_user_id": actor_user_id,
                "idempotency_key": idempotency_key,
            },
        ).mappings().first()
        return dict(row) if row else None

    def create_tenant(
        self,
        *,
        tenant_id: str,
        tenant_code: str,
        tenant_name: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,:tenant_name,'CONFIGURING',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "tenant_code": tenant_code,
                "tenant_name": tenant_name,
                "now": now,
            },
        )

    def tenant_by_id(self, tenant_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc
                FROM security.tenants
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        return dict(row) if row else None

    def tenants(self) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.s.execute(
                text(
                    """
                    SELECT tenant_id,tenant_code,tenant_name,status,
                           created_at_utc,updated_at_utc
                    FROM security.tenants
                    ORDER BY tenant_code
                    """
                )
            ).mappings()
        ]

    def update_tenant_name(self, *, tenant_id: str, tenant_name: str, now: datetime) -> bool:
        row = self.s.execute(
            text(
                """
                UPDATE security.tenants
                SET tenant_name=:tenant_name,updated_at_utc=:now
                WHERE tenant_id=:tenant_id
                RETURNING tenant_id
                """
            ),
            {"tenant_id": tenant_id, "tenant_name": tenant_name, "now": now},
        ).first()
        return row is not None

    def activate_tenant(self, *, tenant_id: str, now: datetime) -> bool:
        row = self.s.execute(
            text(
                """
                UPDATE security.tenants
                SET status='ACTIVE',updated_at_utc=:now
                WHERE tenant_id=:tenant_id AND status='CONFIGURING'
                RETURNING tenant_id
                """
            ),
            {"tenant_id": tenant_id, "now": now},
        ).first()
        return row is not None

    def upsert_self_onboarding_token(
        self,
        *,
        tenant_id: str,
        token_hash: str,
        enabled: bool,
        actor_user_id: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_self_onboarding_settings
                (tenant_id,token_hash,token_version,status,created_by_user_id,created_at_utc,
                 updated_by_user_id,updated_at_utc)
                VALUES (:tenant_id,:token_hash,1,:status,:actor_user_id,:now,
                        :actor_user_id,:now)
                ON CONFLICT (tenant_id) DO UPDATE SET
                    token_hash=EXCLUDED.token_hash,
                    token_version=security.tenant_self_onboarding_settings.token_version + 1,
                    status=EXCLUDED.status,
                    updated_by_user_id=EXCLUDED.updated_by_user_id,
                    updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "tenant_id": tenant_id,
                "token_hash": token_hash,
                "status": "ACTIVE" if enabled else "DISABLED",
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
