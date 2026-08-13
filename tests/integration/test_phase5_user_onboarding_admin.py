from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.repositories.user_admin_repository import UserAdminRepository
from verigence_security.services.user_administration import (
    ExternalIdentityConfiguration,
    UserAdministrationConfiguration,
    UserAdministrationService,
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


def _user_configuration(user_id: str, name: str) -> UserAdministrationConfiguration:
    return UserAdministrationConfiguration(
        user_id=user_id,
        principal_name=name,
        principal_status="ACTIVE",
        display_name=name,
        primary_email=f"{user_id}@example.invalid",
        primary_mobile=None,
        user_status="ACTIVE",
    )


def test_clerk_identity_link_written_by_admin_is_consumed_by_runtime() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    user_id = str(uuid4())
    identity_id = str(uuid4())
    subject = f"phase5-clerk-{uuid4()}"
    now = datetime.now(UTC)

    try:
        with Session(engine) as session:  # type: ignore[arg-type]
            service = UserAdministrationService(UserAdminRepository(session))
            assert service.configure_user(
                configuration=_user_configuration(user_id, "Phase 5 Clerk User"),
                now=now,
            )
            assert service.link_external_identity(
                user_id=user_id,
                configuration=ExternalIdentityConfiguration(
                    external_identity_id=identity_id,
                    provider="CLERK",
                    provider_subject=subject,
                    status="ACTIVE",
                ),
                linked_at=now,
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            runtime = SecurityRepository(session)
            assert runtime.resolve_identity_user("CLERK", subject) == user_id
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.external_identities WHERE user_id=:user_id"),
                {"user_id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id"),
                {"user_id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
        engine.dispose()


def test_external_identity_cannot_be_rebound_to_another_user() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    first_user_id = str(uuid4())
    second_user_id = str(uuid4())
    subject = f"phase5-clerk-conflict-{uuid4()}"
    now = datetime.now(UTC)

    try:
        with Session(engine) as session:  # type: ignore[arg-type]
            service = UserAdministrationService(UserAdminRepository(session))
            assert service.configure_user(
                configuration=_user_configuration(first_user_id, "Phase 5 First User"),
                now=now,
            )
            assert service.configure_user(
                configuration=_user_configuration(second_user_id, "Phase 5 Second User"),
                now=now,
            )
            assert service.link_external_identity(
                user_id=first_user_id,
                configuration=ExternalIdentityConfiguration(
                    external_identity_id=str(uuid4()),
                    provider="CLERK",
                    provider_subject=subject,
                    status="ACTIVE",
                ),
                linked_at=now,
            )
            assert not service.link_external_identity(
                user_id=second_user_id,
                configuration=ExternalIdentityConfiguration(
                    external_identity_id=str(uuid4()),
                    provider="CLERK",
                    provider_subject=subject,
                    status="ACTIVE",
                ),
                linked_at=now,
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            assert SecurityRepository(session).resolve_identity_user("CLERK", subject) == first_user_id
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM security.external_identities "
                    "WHERE user_id IN (:first_id,:second_id)"
                ),
                {"first_id": first_user_id, "second_id": second_user_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id IN (:first_id,:second_id)"),
                {"first_id": first_user_id, "second_id": second_user_id},
            )
            conn.execute(
                text(
                    "DELETE FROM security.security_principals "
                    "WHERE principal_id IN (:first_id,:second_id)"
                ),
                {"first_id": first_user_id, "second_id": second_user_id},
            )
        engine.dispose()


def test_user_admin_does_not_retype_existing_machine_principal() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    principal_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:principal_id,'SYSTEM','Phase 5 Machine','ACTIVE',:now,:now)
                    """
                ),
                {"principal_id": principal_id, "now": now},
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            service = UserAdministrationService(UserAdminRepository(session))
            assert not service.configure_user(
                configuration=_user_configuration(principal_id, "Must Stay Machine"),
                now=now,
            )

        with engine.connect() as conn:
            principal = conn.execute(
                text(
                    "SELECT actor_type,principal_name FROM security.security_principals "
                    "WHERE principal_id=:principal_id"
                ),
                {"principal_id": principal_id},
            ).mappings().one()
            user_count = conn.execute(
                text("SELECT count(*) FROM security.users WHERE user_id=:principal_id"),
                {"principal_id": principal_id},
            ).scalar_one()
        assert principal["actor_type"] == "SYSTEM"
        assert principal["principal_name"] == "Phase 5 Machine"
        assert user_count == 0
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:principal_id"),
                {"principal_id": principal_id},
            )
        engine.dispose()
