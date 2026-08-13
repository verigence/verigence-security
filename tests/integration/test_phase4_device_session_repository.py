from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from verigence_security.repositories.device_session_repository import (
    DeviceSessionLifecycleRepository,
)

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


@dataclass(frozen=True, slots=True)
class Phase4Ids:
    tenant_id: str
    user_id: str
    membership_id: str
    active_device_id: str
    pending_device_id: str
    blocked_device_id: str
    revoked_device_id: str
    enrollment_request_id: str
    location_id: str
    access_session_id: str


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


@pytest.fixture()
def phase4_fixture() -> tuple[object, Phase4Ids]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    ids = Phase4Ids(
        tenant_id=str(uuid4()),
        user_id=str(uuid4()),
        membership_id=str(uuid4()),
        active_device_id=str(uuid4()),
        pending_device_id=str(uuid4()),
        blocked_device_id=str(uuid4()),
        revoked_device_id=str(uuid4()),
        enrollment_request_id=str(uuid4()),
        location_id=str(uuid4()),
        access_session_id=str(uuid4()),
    )
    now = datetime.now(UTC)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,'Phase 4 integration','ACTIVE',:now,:now)
                """
            ),
            {"tenant_id": ids.tenant_id, "tenant_code": f"p4-{ids.tenant_id}", "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER','Phase 4 integration','ACTIVE',:now,:now)
                """
            ),
            {"user_id": ids.user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'Phase 4 integration','ACTIVE',:now,:now)
                """
            ),
            {"user_id": ids.user_id, "now": now},
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
                "membership_id": ids.membership_id,
                "tenant_id": ids.tenant_id,
                "user_id": ids.user_id,
                "now": now,
            },
        )
        for device_id, status in (
            (ids.active_device_id, "ACTIVE"),
            (ids.pending_device_id, "PENDING"),
            (ids.blocked_device_id, "BLOCKED"),
            (ids.revoked_device_id, "REVOKED"),
        ):
            conn.execute(
                text(
                    """
                    INSERT INTO security.registered_devices
                    (device_id,tenant_id,user_id,device_type,platform,device_name,status,
                     registered_at_utc)
                    VALUES (:device_id,:tenant_id,:user_id,'WEB','LINUX',
                            'Phase 4 integration',:status,:now)
                    """
                ),
                {
                    "device_id": device_id,
                    "tenant_id": ids.tenant_id,
                    "user_id": ids.user_id,
                    "status": status,
                    "now": now,
                },
            )
        conn.execute(
            text(
                """
                INSERT INTO security.device_enrollment_requests
                (enrollment_request_id,tenant_id,user_id,device_id,source_ip,
                 requested_at_utc,status)
                VALUES (:request_id,:tenant_id,:user_id,:device_id,'203.0.113.10',
                        :now,'PENDING')
                """
            ),
            {
                "request_id": ids.enrollment_request_id,
                "tenant_id": ids.tenant_id,
                "user_id": ids.user_id,
                "device_id": ids.pending_device_id,
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
                VALUES (:location_id,:tenant_id,'phase4','Phase 4 location','OFFICE',
                        28.613900,77.209000,1000,'UTC','ACTIVE',:now,:now)
                """
            ),
            {"location_id": ids.location_id, "tenant_id": ids.tenant_id, "now": now},
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
                "session_id": ids.access_session_id,
                "tenant_id": ids.tenant_id,
                "user_id": ids.user_id,
                "membership_id": ids.membership_id,
                "device_id": ids.active_device_id,
                "location_id": ids.location_id,
                "now": now,
                "expires_at": now + timedelta(minutes=10),
            },
        )

    try:
        yield engine, ids
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.access_context_evaluations WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.access_sessions WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.device_enrollment_requests WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.registered_devices WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_locations WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_memberships WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:id"),
                {"id": ids.user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": ids.user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": ids.tenant_id},
            )
        engine.dispose()


def test_active_device_count_ignores_non_active_states(
    phase4_fixture: tuple[object, Phase4Ids],
) -> None:
    engine, ids = phase4_fixture
    with Session(engine) as session:  # type: ignore[arg-type]
        repository = DeviceSessionLifecycleRepository(session)
        count = repository.count_active_devices(
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        assert count == 1


def test_membership_lock_serializes_device_limit_decisions(
    phase4_fixture: tuple[object, Phase4Ids],
) -> None:
    engine, ids = phase4_fixture
    first = Session(engine)  # type: ignore[arg-type]
    second = Session(engine)  # type: ignore[arg-type]
    try:
        first_repo = DeviceSessionLifecycleRepository(first)
        second_repo = DeviceSessionLifecycleRepository(second)
        locked = first_repo.lock_membership_for_device_limit(
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        assert locked is not None

        second.execute(text("SET LOCAL lock_timeout = '500ms'"))
        with pytest.raises(OperationalError):
            second_repo.lock_membership_for_device_limit(
                tenant_id=ids.tenant_id,
                user_id=ids.user_id,
            )
        second.rollback()
        first.rollback()

        reacquired = second_repo.lock_membership_for_device_limit(
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        assert reacquired is not None
        second.rollback()
    finally:
        first.close()
        second.close()


def test_pending_device_activation_updates_device_and_request_together(
    phase4_fixture: tuple[object, Phase4Ids],
) -> None:
    engine, ids = phase4_fixture
    now = datetime.now(UTC)
    with Session(engine) as session:  # type: ignore[arg-type]
        repository = DeviceSessionLifecycleRepository(session)
        pending = repository.pending_device_for_update(
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
            device_id=ids.pending_device_id,
        )
        assert pending is not None
        activated = repository.activate_pending_device(
            enrollment_request_id=ids.enrollment_request_id,
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
            device_id=ids.pending_device_id,
            decided_by_user_id=ids.user_id,
            decided_at=now,
        )
        assert activated is True
        repository.commit()

    with engine.connect() as conn:  # type: ignore[union-attr]
        device_status = conn.execute(
            text("SELECT status FROM security.registered_devices WHERE device_id=:id"),
            {"id": ids.pending_device_id},
        ).scalar_one()
        request_status = conn.execute(
            text(
                "SELECT status FROM security.device_enrollment_requests "
                "WHERE enrollment_request_id=:id"
            ),
            {"id": ids.enrollment_request_id},
        ).scalar_one()
    assert device_status == "ACTIVE"
    assert request_status == "APPROVED"


def test_session_revocation_is_scoped_and_idempotent(
    phase4_fixture: tuple[object, Phase4Ids],
) -> None:
    engine, ids = phase4_fixture
    with Session(engine) as session:  # type: ignore[arg-type]
        repository = DeviceSessionLifecycleRepository(session)
        locked = repository.user_session_for_update(
            access_session_id=ids.access_session_id,
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        assert locked is not None
        assert locked["status"] == "ACTIVE"
        assert repository.revoke_active_user_session(
            access_session_id=ids.access_session_id,
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        repository.commit()

    with Session(engine) as session:  # type: ignore[arg-type]
        repository = DeviceSessionLifecycleRepository(session)
        locked = repository.user_session_for_update(
            access_session_id=ids.access_session_id,
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        assert locked is not None
        assert locked["status"] == "REVOKED"
        assert not repository.revoke_active_user_session(
            access_session_id=ids.access_session_id,
            tenant_id=ids.tenant_id,
            user_id=ids.user_id,
        )
        repository.rollback()


def test_postgresql_enforces_one_active_session_per_user_device(
    phase4_fixture: tuple[object, Phase4Ids],
) -> None:
    engine, ids = phase4_fixture
    now = datetime.now(UTC)
    duplicate_session_id = str(uuid4())
    with pytest.raises(IntegrityError), engine.begin() as conn:  # type: ignore[union-attr]
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
                "session_id": duplicate_session_id,
                "tenant_id": ids.tenant_id,
                "user_id": ids.user_id,
                "membership_id": ids.membership_id,
                "device_id": ids.active_device_id,
                "location_id": ids.location_id,
                "now": now,
                "expires_at": now + timedelta(minutes=10),
            },
        )
