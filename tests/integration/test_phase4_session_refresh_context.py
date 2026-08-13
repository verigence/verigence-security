from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.session_refresh_repository import (
    SessionRefreshRepository,
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


def test_refresh_repository_moves_active_session_to_new_approved_location() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    membership_id = str(uuid4())
    device_id = str(uuid4())
    old_location_id = str(uuid4())
    new_location_id = str(uuid4())
    access_session_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 4 refresh context',
                            'ACTIVE',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p4-refresh-{tenant_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 4 refresh context','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 4 refresh context','ACTIVE',:now,:now)
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
                            'Phase 4 refresh context','ACTIVE',:now)
                    """
                ),
                {
                    "device_id": device_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "now": now,
                },
            )
            for location_id, code, latitude, longitude in (
                (old_location_id, "old", 28.613900, 77.209000),
                (new_location_id, "new", 28.704100, 77.102500),
            ):
                conn.execute(
                    text(
                        """
                        INSERT INTO security.tenant_locations
                        (location_id,tenant_id,location_code,location_name,location_type,
                         latitude,longitude,allowed_radius_meters,timezone_iana,status,
                         created_at_utc,updated_at_utc)
                        VALUES (:location_id,:tenant_id,:code,:name,'OFFICE',
                                :latitude,:longitude,500,'UTC','ACTIVE',:now,:now)
                        """
                    ),
                    {
                        "location_id": location_id,
                        "tenant_id": tenant_id,
                        "code": f"{code}-{location_id}",
                        "name": f"Phase 4 {code}",
                        "latitude": latitude,
                        "longitude": longitude,
                        "now": now,
                    },
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
                            :device_id,:old_location_id,'DEV_MOCK',1,'203.0.113.10',
                            'NOT_DETECTED',:now,:expires_at,:now,:now,'ACTIVE')
                    """
                ),
                {
                    "session_id": access_session_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "membership_id": membership_id,
                    "device_id": device_id,
                    "old_location_id": old_location_id,
                    "now": now,
                    "expires_at": now + timedelta(minutes=10),
                },
            )

        refreshed_at = datetime.now(UTC)
        with Session(engine) as session:  # type: ignore[arg-type]
            repository = SessionRefreshRepository(session)
            locked = repository.user_session_for_update(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
            )
            assert locked is not None
            assert str(locked["location_id"]) == old_location_id

            assert repository.update_active_session_context(
                access_session_id=access_session_id,
                tenant_id=tenant_id,
                user_id=user_id,
                location_id=new_location_id,
                source_ip="203.0.113.20",
                vpn_status="NOT_DETECTED",
                authorization_version=2,
                expires_at=refreshed_at + timedelta(minutes=8),
                now=refreshed_at,
            )
            repository.commit()

        with engine.connect() as conn:
            row = conn.execute(
                text(
                    """
                    SELECT location_id,source_ip::text,authorization_version,status
                    FROM security.access_sessions
                    WHERE access_session_id=:id
                    """
                ),
                {"id": access_session_id},
            ).mappings().one()

        assert str(row["location_id"]) == new_location_id
        assert row["source_ip"] == "203.0.113.20"
        assert row["authorization_version"] == 2
        assert row["status"] == "ACTIVE"
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
