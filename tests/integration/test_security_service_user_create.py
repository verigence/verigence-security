from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.v2_platform_user_create import V2PlatformUserCreateService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _sqlalchemy_url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url.removeprefix(prefix)
    return url


class _FakeClerk:
    def __init__(self) -> None:
        self.created: list[str] = []
        self.deleted: list[str] = []

    def create_user(self, *, first_name: str, last_name: str, email: str, password: str) -> str:
        self.created.append(email)
        return f"user_created_{uuid4().hex}"

    def delete_user(self, clerk_user_id: str) -> None:
        self.deleted.append(clerk_user_id)


@pytest.fixture
def session() -> Iterator[Session]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    conn = engine.connect()
    outer = conn.begin()
    db = Session(bind=conn, join_transaction_mode="create_savepoint")
    try:
        yield db
    finally:
        db.close()
        outer.rollback()
        conn.close()
        engine.dispose()


def _seed_integration(db: Session) -> str:
    principal_id = str(uuid4())
    now = datetime.now(UTC)
    db.execute(
        text(
            "INSERT INTO security.security_principals VALUES "
            "(:id,'SERVICE_INTEGRATION',:name,'ACTIVE',:now,:now)"
        ),
        {"id": principal_id, "name": f"hrmgmt-{principal_id[:8]}", "now": now},
    )
    db.execute(
        text(
            "INSERT INTO security.service_integrations (principal_id,integration_key,created_at_utc)"
            " VALUES (:id,:key,:now)"
        ),
        {"id": principal_id, "key": f"hrmgmt-{principal_id[:8]}", "now": now},
    )
    return principal_id


def _create(db: Session, clerk: _FakeClerk, principal_id: str, *, email: str, mobile: str = "9000000001"):
    return V2PlatformUserCreateService(db).create_for_service(
        first_name="Asha",
        last_name="Rao",
        email=email,
        mobile=mobile,
        password="not-stored",
        service_principal_id=principal_id,
        service_integration_key="hrmgmt",
        correlation_id=str(uuid4()),
        clerk=clerk,
    )


def test_service_creates_a_pending_user_and_records_the_integration(session: Session) -> None:
    principal_id = _seed_integration(session)
    clerk = _FakeClerk()
    email = f"emp.{uuid4().hex[:8]}@example.test"
    created = _create(session, clerk, principal_id, email=email)

    row = session.execute(
        text(
            """
            SELECT u.status,u.is_employee,u.primary_email,u.primary_mobile,p.status AS principal_status,
                   e.provider_subject
            FROM security.users u
            JOIN security.security_principals p ON p.principal_id=u.user_id
            JOIN security.external_identities e ON e.user_id=u.user_id AND e.provider='CLERK'
            WHERE u.user_id=:id
            """
        ),
        {"id": created.user_id},
    ).mappings().one()
    assert row["status"] == "PENDING" and row["principal_status"] == "ACTIVE"
    assert row["is_employee"] is True
    assert row["primary_email"] == email and row["primary_mobile"] == "+919000000001"
    assert row["provider_subject"] == created.clerk_subject

    event = session.execute(
        text(
            "SELECT principal_id::text,actor_type,outcome,payload_json::text"
            " FROM security.security_events"
            " WHERE event_type='SERVICE_USER_CREATE' AND entity_id=:id"
        ),
        {"id": created.user_id},
    ).one()
    assert event[0] == principal_id and event[1] == "SERVICE_INTEGRATION" and event[2] == "SUCCESS"
    assert "not-stored" not in event[3] and "password" not in event[3].lower()
    # a service call never writes a human-actor admin record
    assert session.execute(
        text("SELECT count(*) FROM security.admin_change_records WHERE resource_id=:id"),
        {"id": created.user_id},
    ).scalar_one() == 0


def test_duplicate_email_is_refused_and_the_provider_account_is_discarded(session: Session) -> None:
    principal_id = _seed_integration(session)
    clerk = _FakeClerk()
    email = f"dup.{uuid4().hex[:8]}@example.test"
    _create(session, clerk, principal_id, email=email, mobile="9000000002")
    with pytest.raises(ValueError):
        _create(session, clerk, principal_id, email=email, mobile="9000000003")
    # the second attempt was refused before any provider account was made
    assert len(clerk.created) == 1


def test_invalid_mobile_is_refused_before_anything_is_created(session: Session) -> None:
    from verigence_security.services.v2_platform_user_create import InvalidUserInput

    principal_id = _seed_integration(session)
    clerk = _FakeClerk()
    with pytest.raises(InvalidUserInput):
        _create(session, clerk, principal_id, email=f"x.{uuid4().hex[:8]}@example.test", mobile="12345")
    assert clerk.created == []
