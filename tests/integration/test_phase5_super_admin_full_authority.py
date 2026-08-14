from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.tenant_rbac_gate import TenantRbacGateService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(value: str) -> str:
    if value.startswith("postgresql+psycopg://"):
        return value
    if value.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql+asyncpg://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be PostgreSQL")


def test_super_admin_owns_every_active_permission_and_future_permissions() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            transaction = conn.begin()
            try:
                active_permissions = set(
                    conn.execute(
                        text(
                            "SELECT permission_key FROM security.permissions "
                            "WHERE status='ACTIVE'"
                        )
                    ).scalars()
                )
                super_admin_permissions = set(
                    conn.execute(
                        text(
                            "SELECT permission_key FROM security.platform_role_permissions "
                            "WHERE role_key='platform.super_admin'"
                        )
                    ).scalars()
                )
                assert super_admin_permissions == active_permissions

                probe_key = f"security.super_admin_probe.{uuid4().hex[:12]}"
                now = datetime.now(UTC)
                conn.execute(
                    text(
                        """
                        INSERT INTO security.permissions
                        (permission_key,module_key,resource_key,action_key,description,status,
                         display_name,catalog_version,updated_at_utc)
                        VALUES (:key,'security','super_admin_probe','verify',NULL,'ACTIVE',
                                'Super Admin Probe','test',:now)
                        """
                    ),
                    {"key": probe_key, "now": now},
                )
                assert conn.execute(
                    text(
                        """
                        SELECT 1 FROM security.platform_role_permissions
                        WHERE role_key='platform.super_admin' AND permission_key=:key
                        """
                    ),
                    {"key": probe_key},
                ).first() is not None

                conn.execute(
                    text(
                        "UPDATE security.permissions SET status='RETIRED',updated_at_utc=:now "
                        "WHERE permission_key=:key"
                    ),
                    {"key": probe_key, "now": now},
                )
                assert conn.execute(
                    text(
                        """
                        SELECT 1 FROM security.platform_role_permissions
                        WHERE role_key='platform.super_admin' AND permission_key=:key
                        """
                    ),
                    {"key": probe_key},
                ).first() is None
            finally:
                transaction.rollback()
    finally:
        engine.dispose()


def test_super_admin_can_administer_tenant_without_tenant_role_assignment() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            transaction = conn.begin()
            try:
                now = datetime.now(UTC)
                user_id = str(uuid4())
                tenant_id = str(uuid4())
                assignment_id = str(uuid4())
                conn.execute(
                    text(
                        """
                        INSERT INTO security.security_principals
                        (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                        VALUES (:user_id,'USER',:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"user_id": user_id, "name": f"super-admin-test-{user_id}", "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.users
                        (user_id,display_name,status,created_at_utc,updated_at_utc)
                        VALUES (:user_id,:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"user_id": user_id, "name": "Super Admin Test", "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.tenants
                        (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                        VALUES (:tenant_id,:code,'Super Admin Test Tenant','ACTIVE',:now,:now)
                        """
                    ),
                    {
                        "tenant_id": tenant_id,
                        "code": f"SA-{uuid4().hex[:10]}",
                        "now": now,
                    },
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.platform_user_role_assignments
                        (assignment_id,user_id,role_key,status,assignment_source,assigned_at_utc)
                        VALUES (:assignment_id,:user_id,'platform.super_admin','ACTIVE',
                                'BOOTSTRAP',:now)
                        """
                    ),
                    {"assignment_id": assignment_id, "user_id": user_id, "now": now},
                )

                session = Session(bind=conn)
                roles, permissions = TenantRbacGateService(session).authorize_user(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    permission_key="security.role.create",
                )
                assert "platform.super_admin" in roles
                assert "security.role.create" in permissions
                assert conn.execute(
                    text(
                        """
                        SELECT 1 FROM security.user_role_assignments
                        WHERE user_id=:user_id AND tenant_id=:tenant_id AND status='ACTIVE'
                        """
                    ),
                    {"user_id": user_id, "tenant_id": tenant_id},
                ).first() is None
            finally:
                transaction.rollback()
    finally:
        engine.dispose()
