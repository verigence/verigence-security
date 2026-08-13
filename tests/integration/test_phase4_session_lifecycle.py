from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.device_session_repository import (
    DeviceSessionLifecycleRepository,
)
from verigence_security.services.session_lifecycle import UserSessionLifecycleService

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


def test_revoke_service_persists_active_to_revoked_on_neon() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    membership_id = str(uuid4())
    device_id = str(uuid4())
    location_id = str(uuid4())
    access_session_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 4 session lifecycle',
                            'ACTIVE',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p4-session-{tenant_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 4 session lifecycle','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 4 session lifecycle','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenant_memberships
                    (membership_id,tenant_id,user_id,status,authorization_version,
                     created_at_utc,updated_at_utc)
                    VALUES (:membership_id,:tenant_id,:user_id,'ACTIVE',1,:now,:now)
                    """
                ),
                {
                    "membership_id": membership_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.registered_devices
                    (device_id,tenant_id,user_id,device_type,platform,device_name,status,
                     registered_at_utc)
                    VALUES (:device_id,:tenant_id,:user_id,'WEB','LINUX',
                            'Phase 4 session lifecycle','ACTIVE',:now)
                    """
                ),
                {
                    "device_id": device_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenant_locations
                    (location_id,tenant_id,location_code,location_name,location_type,
                     latitude,longitude,allowed_radius_meters,timezone_iana,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:location_id,:tenant_id,'phase4-session','Phase 4 session',
                            'OFFICE',28.613900,77.209000,1000,'UTC','ACTIVE',:now,:now)
                    """
                ),
                {"location_id": location_id, "tenant_id": tenant_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.access_sessions
                    (access_session_id,tenant_id,principal_id,actor_type,membership_id,
                     device_id,location_id,authentication_source,authorization_version,
                     source_ip,vpn_status,started_at_utc,expires_at_utc,last_activity_at_utc,
                     last_geo_validated_at_utc,status)
                    VALUES (:session_id,:tenant_id,:user_id,'USER',:membership_id,
                            :device_id,:location_id,'DEV_MOCK',1,'203.0.113.10',
                            'NOT_DETECTED',:now,:expires_at,:now,:now,'ACTIVE')
                    """
                ),
                {
                    "session_id": access_session_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "membership_id": membership_id,
                    "device_id": device_id,
                    "location_id": location_id,
                    "now": now,
                    "expires_at": now + timedelta(minutes=10),
                },
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            repository = DeviceSessionLifecycleRepository(session)
            service = UserSessionLifecycleService(repository)
            assert service.revoke(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )

        with engine.connect() as conn:
            status = conn.execute(
                text("SELECT status FROM security.access_sessions WHERE access_session_id=:id"),
                {"id": access_session_id},
            ).scalar_one()
        assert status == "REVOKED"

        with Session(engine) as session:  # type: ignore[arg-type]
            repository = DeviceSessionLifecycleRepository(session)
            service = UserSessionLifecycleService(repository)
            assert not service.revoke(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.access_sessions WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.registered_devices WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_locations WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_memberships WHERE tenant_id=:id"),
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
