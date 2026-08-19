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


def _create_user(
    conn: object,
    *,
    user_id: str,
    name: str,
    user_status: str,
    now: datetime,
) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.security_principals
            (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,'USER',:name,'ACTIVE',:now,:now)
            """
        ),
        {"user_id": user_id, "name": name, "now": now},
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.users
            (user_id,display_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,:name,:user_status,:now,:now)
            """
        ),
        {"user_id": user_id, "name": name, "user_status": user_status, "now": now},
    )


def test_pending_user_cannot_receive_new_v2_operating_role() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    actor_id = str(uuid4())
    pending_user_id = str(uuid4())
    tenant_id = str(uuid4())
    try:
        with engine.begin() as conn:
            _create_user(
                conn,
                user_id=actor_id,
                name="V2 active actor",
                user_status="ACTIVE",
                now=now,
            )
            _create_user(
                conn,
                user_id=pending_user_id,
                name="V2 pending subject",
                user_status="PENDING",
                now=now,
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:code,:code,'ACTIVE',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "code": f"v2-active-user-{tenant_id}",
                    "now": now,
                },
            )

        with Session(engine) as session, pytest.raises(
            ValueError,
            match="USER must be ACTIVE for an operating-role assignment",
        ):
            OperatingRoleAssignmentService(session).set_role(
                tenant_id=tenant_id,
                user_id=pending_user_id,
                role_key="PC",
                actor_user_id=actor_id,
            )

        with engine.connect() as conn:
            count = conn.execute(
                text(
                    """
                    SELECT count(*)
                    FROM security.user_tenant_operating_roles
                    WHERE user_id=:user_id
                    """
                ),
                {"user_id": pending_user_id},
            ).scalar_one()
            assert int(count) == 0
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM security.user_tenant_operating_roles WHERE user_id=:user_id"
                ),
                {"user_id": pending_user_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id"),
                {"user_id": pending_user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                {"user_id": pending_user_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id"),
                {"user_id": actor_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                {"user_id": actor_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
        engine.dispose()
