from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.core.errors import SecurityError
from verigence_security.repositories.security_repository import SecurityRepository

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


@pytest.mark.parametrize("device_status", ["BLOCKED", "REVOKED"])
def test_nonactive_registered_device_is_rejected(device_status: str) -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    device_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 4 nonactive device',
                            'ACTIVE',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p4-device-gate-{tenant_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 4 nonactive device','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 4 nonactive device','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.registered_devices
                    (device_id,tenant_id,user_id,device_type,platform,device_name,status,
                     registered_at_utc)
                    VALUES (:device_id,:tenant_id,:user_id,'WEB','LINUX',
                            'Phase 4 nonactive device',:status,:now)
                    """
                ),
                {
                    "device_id": device_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "status": device_status,
                    "now": now,
                },
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            repository = SecurityRepository(session)
            with pytest.raises(SecurityError) as exc_info:
                repository.lock_active_device(user_id, tenant_id, device_id)
            assert exc_info.value.code == "DEVICE_NOT_ACTIVE"
            session.rollback()
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.registered_devices WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()
