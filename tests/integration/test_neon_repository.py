from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from verigence_security.repositories.security_repository import SecurityRepository

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


@dataclass(frozen=True, slots=True)
class FixtureIds:
    tenant_id: str
    user_id: str
    membership_id: str
    device_id: str


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL")


@pytest.fixture()
def neon_fixture() -> tuple[object, FixtureIds]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    ids = FixtureIds(
        tenant_id=str(uuid4()),
        user_id=str(uuid4()),
        membership_id=str(uuid4()),
        device_id=str(uuid4()),
    )
    now = datetime.now(UTC)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                  (tenant_id, tenant_code, tenant_name, status, created_at_utc, updated_at_utc)
                VALUES
                  (:tenant_id, :tenant_code, 'Neon integration fixture', 'ACTIVE', :now, :now)
                """
            ),
            {"tenant_id": ids.tenant_id, "tenant_code": f"it-{ids.tenant_id}", "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                  (principal_id, actor_type, principal_name, status, created_at_utc, updated_at_utc)
                VALUES
                  (:user_id, 'USER', 'Neon integration fixture', 'ACTIVE', :now, :now)
                """
            ),
            {"user_id": ids.user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                  (user_id, display_name, status, created_at_utc, updated_at_utc)
                VALUES
                  (:user_id, 'Neon integration fixture', 'ACTIVE', :now, :now)
                """
            ),
            {"user_id": ids.user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.tenant_memberships
                  (membership_id, tenant_id, user_id, status, authorization_version,
                   created_at_utc, updated_at_utc)
                VALUES
                  (:membership_id, :tenant_id, :user_id, 'ACTIVE', 1, :now, :now)
                """
            ),
            {
                "membership_id": ids.membership_id,
                "tenant_id": ids.tenant_id,
                "user_id": ids.user_id,
                "now": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO security.registered_devices
                  (device_id, tenant_id, user_id, device_type, platform, device_name,
                   status, registered_at_utc)
                VALUES
                  (:device_id, :tenant_id, :user_id, 'WEB', 'LINUX',
                   'Neon integration fixture', 'ACTIVE', :now)
                """
            ),
            {
                "device_id": ids.device_id,
                "tenant_id": ids.tenant_id,
                "user_id": ids.user_id,
                "now": now,
            },
        )

    try:
        yield engine, ids
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.registered_devices WHERE device_id=:device_id"),
                {"device_id": ids.device_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_memberships WHERE membership_id=:membership_id"),
                {"membership_id": ids.membership_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id"),
                {"user_id": ids.user_id},
            )
            conn.execute(
                text(
                    "DELETE FROM security.security_principals WHERE principal_id=:principal_id"
                ),
                {"principal_id": ids.user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": ids.tenant_id},
            )
        engine.dispose()


def test_repository_reads_real_neon_user_context(neon_fixture: tuple[object, FixtureIds]) -> None:
    engine, ids = neon_fixture

    with Session(engine) as session:  # type: ignore[arg-type]
        repository = SecurityRepository(session)
        assert repository.tenant_status(ids.tenant_id) == "ACTIVE"
        context = repository.get_user_context(ids.user_id, ids.tenant_id, datetime.now(UTC))
        assert context.user_id == ids.user_id
        assert context.membership_id == ids.membership_id
        assert context.authorization_version == 1


def test_repository_device_for_update_serializes_concurrent_access(
    neon_fixture: tuple[object, FixtureIds],
) -> None:
    engine, ids = neon_fixture

    first = Session(engine)  # type: ignore[arg-type]
    second = Session(engine)  # type: ignore[arg-type]
    try:
        first_repo = SecurityRepository(first)
        second_repo = SecurityRepository(second)

        locked = first_repo.lock_active_device(ids.user_id, ids.tenant_id, ids.device_id)
        assert str(locked["device_id"]) == ids.device_id

        second.execute(text("SET LOCAL lock_timeout = '500ms'"))
        with pytest.raises(OperationalError):
            second_repo.lock_active_device(ids.user_id, ids.tenant_id, ids.device_id)
        second.rollback()

        first.rollback()

        reacquired = second_repo.lock_active_device(ids.user_id, ids.tenant_id, ids.device_id)
        assert str(reacquired["device_id"]) == ids.device_id
        second.rollback()
    finally:
        first.close()
        second.close()


def test_actor_type_check_constraint_is_enforced(neon_fixture: tuple[object, FixtureIds]) -> None:
    engine, _ = neon_fixture
    invalid_id = str(uuid4())
    now = datetime.now(UTC)

    with pytest.raises(IntegrityError), engine.begin() as conn:  # type: ignore[union-attr]
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                  (principal_id, actor_type, principal_name, status,
                   created_at_utc, updated_at_utc)
                VALUES
                  (:principal_id, 'INVALID_ACTOR', 'invalid fixture', 'ACTIVE', :now, :now)
                """
            ),
            {"principal_id": invalid_id, "now": now},
        )


def test_user_principal_foreign_key_is_enforced(neon_fixture: tuple[object, FixtureIds]) -> None:
    engine, _ = neon_fixture
    missing_principal_id = str(uuid4())
    now = datetime.now(UTC)

    with pytest.raises(IntegrityError), engine.begin() as conn:  # type: ignore[union-attr]
        conn.execute(
            text(
                """
                INSERT INTO security.users
                  (user_id, display_name, status, created_at_utc, updated_at_utc)
                VALUES
                  (:user_id, 'missing principal fixture', 'ACTIVE', :now, :now)
                """
            ),
            {"user_id": missing_principal_id, "now": now},
        )
