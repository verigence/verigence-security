from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.v2_rbac import OperatingRoleAssignmentService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL")


def test_inactive_tenant_cannot_receive_new_operating_role() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    actor_id = str(uuid4())
    user_id = str(uuid4())
    tenant_id = str(uuid4())
    try:
        with engine.begin() as conn:
            for current_user, name in ((actor_id, "actor"), (user_id, "subject")):
                conn.execute(
                    text(
                        """
                        INSERT INTO security.security_principals
                        (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                        VALUES (:user_id,'USER',:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"user_id": current_user, "name": name, "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.users
                        (user_id,display_name,status,created_at_utc,updated_at_utc)
                        VALUES (:user_id,:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"user_id": current_user, "name": name, "now": now},
                )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:code,:code,'SUSPENDED',:now,:now)
                    """
                ),
                {"tenant_id": tenant_id, "code": f"inactive-{tenant_id}", "now": now},
            )

        with Session(engine) as session:
            with pytest.raises(
                ValueError,
                match="Tenant must be ACTIVE for an operating-role assignment",
            ):
                OperatingRoleAssignmentService(session).set_role(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    role_key="PC",
                    actor_user_id=actor_id,
                )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM security.user_tenant_operating_roles "
                    "WHERE user_id IN (:actor_id,:user_id)"
                ),
                {"actor_id": actor_id, "user_id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
            for current_user in (actor_id, user_id):
                conn.execute(
                    text("DELETE FROM security.users WHERE user_id=:user_id"),
                    {"user_id": current_user},
                )
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                    {"user_id": current_user},
                )
        engine.dispose()
