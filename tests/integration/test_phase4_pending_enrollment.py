from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.device_session_repository import (
    DeviceSessionLifecycleRepository,
)

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


def test_create_pending_enrollment_persists_only_pending_state() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    device_id = str(uuid4())
    request_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 4 pending enrollment',
                            'ACTIVE',:now,:now)
                    """
                ),
                {"tenant_id": tenant_id, "tenant_code": f"p4-pending-{tenant_id}", "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 4 pending enrollment','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 4 pending enrollment','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            repository = DeviceSessionLifecycleRepository(session)
            repository.create_pending_enrollment(
                enrollment_request_id=request_id,
                device_id=device_id,
                tenant_id=tenant_id,
                user_id=user_id,
                device_type="MOBILE",
                platform="ANDROID",
                device_name="Phase 4 mobile",
                device_model="DEV-TEST",
                os_version="test",
                browser_name=None,
                browser_version=None,
                app_version="0.2-test",
                platform_device_identifier="phase4-test-id",
                mac_address=None,
                source_ip="203.0.113.10",
                latitude=28.6139,
                longitude=77.2090,
                accuracy_meters=10,
                now=now,
            )
            repository.commit()

        with engine.connect() as conn:
            device_status = conn.execute(
                text("SELECT status FROM security.registered_devices WHERE device_id=:id"),
                {"id": device_id},
            ).scalar_one()
            request_status = conn.execute(
                text(
                    "SELECT status FROM security.device_enrollment_requests "
                    "WHERE enrollment_request_id=:id"
                ),
                {"id": request_id},
            ).scalar_one()
        assert device_status == "PENDING"
        assert request_status == "PENDING"
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.device_enrollment_requests WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.registered_devices WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(text("DELETE FROM security.users WHERE user_id=:id"), {"id": user_id})
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": user_id},
            )
            conn.execute(text("DELETE FROM security.tenants WHERE tenant_id=:id"), {"id": tenant_id})
        engine.dispose()
