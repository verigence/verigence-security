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
        self.banned: list[str] = []

    def create_user(self, *, first_name: str, last_name: str, email: str, password: str) -> str:
        self.created.append(email)
        return f"user_created_{uuid4().hex}"

    def delete_user(self, clerk_user_id: str) -> None:
        self.deleted.append(clerk_user_id)

    def ban_user(self, clerk_user_id: str) -> None:
        self.banned.append(clerk_user_id)


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


def test_service_creates_an_active_employee_and_records_the_integration(session: Session) -> None:
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
    assert row["status"] == "ACTIVE" and row["principal_status"] == "ACTIVE"
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


def _sync(db: Session, clerk: _FakeClerk, principal_id: str, user_id: str, *, suspend: bool):
    from verigence_security.services.v2_user_lifecycle import V2UserLifecycleService

    return V2UserLifecycleService(db).sync_employee_for_service(
        user_id=user_id,
        suspend=suspend,
        principal_id=principal_id,
        integration_key="hrmgmt",
        correlation_id=str(uuid4()),
        clerk=clerk,  # type: ignore[arg-type]
    )


def _active_user(db: Session, clerk: _FakeClerk, principal_id: str) -> str:
    created = _create(db, clerk, principal_id, email=f"sync.{uuid4().hex[:8]}@example.test")
    db.execute(
        text("UPDATE security.users SET status='ACTIVE', is_employee=false WHERE user_id=:id"),
        {"id": created.user_id},
    )
    return created.user_id


def test_employee_sync_ticks_the_flag_and_suspends_only_when_asked(session: Session) -> None:
    principal_id = _seed_integration(session)
    clerk = _FakeClerk()
    uid = _active_user(session, clerk, principal_id)

    first = _sync(session, clerk, principal_id, uid, suspend=False)
    assert first.found and first.ticked and not first.suspended and first.status == "ACTIVE"
    again = _sync(session, clerk, principal_id, uid, suspend=False)
    assert not again.ticked and not again.suspended  # nothing left to change

    done = _sync(session, clerk, principal_id, uid, suspend=True)
    assert done.suspended and done.status == "SUSPENDED" and len(clerk.banned) == 1
    row = session.execute(
        text("SELECT status,is_employee FROM security.users WHERE user_id=:id"), {"id": uid}
    ).one()
    assert row[0] == "SUSPENDED" and row[1] is True
    event = session.execute(
        text(
            "SELECT count(*) FROM security.security_events"
            " WHERE event_type='SERVICE_EMPLOYEE_SYNC' AND entity_id=:id"
        ),
        {"id": uid},
    ).scalar_one()
    assert event == 2  # one for the tick, one for the suspension

    # an already suspended user is left alone, and a missing one is reported
    left = _sync(session, clerk, principal_id, uid, suspend=True)
    assert left.note == "NOT_ACTIVE" and not left.suspended and len(clerk.banned) == 1
    assert _sync(session, clerk, principal_id, str(uuid4()), suspend=True).found is False


def test_employee_sync_never_suspends_the_active_super_admin(session: Session) -> None:
    principal_id = _seed_integration(session)
    clerk = _FakeClerk()
    existing = session.execute(
        text(
            "SELECT user_id::text FROM security.user_admin_role_assignments"
            " WHERE role_key='SuperAdmin' AND status='ACTIVE' LIMIT 1"
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = _active_user(session, clerk, principal_id)
        session.execute(
            text(
                "INSERT INTO security.user_admin_role_assignments"
                " (assignment_id,user_id,role_key,scope_type,scope_id,status,assigned_at_utc)"
                " VALUES (:aid,:id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',now())"
            ),
            {"aid": str(uuid4()), "id": existing},
        )
    session.execute(
        text("UPDATE security.users SET status='ACTIVE' WHERE user_id=:id"), {"id": existing}
    )
    out = _sync(session, clerk, principal_id, existing, suspend=True)
    assert out.note == "SUPER_ADMIN_PROTECTED" and not out.suspended and clerk.banned == []
    assert session.execute(
        text("SELECT status FROM security.users WHERE user_id=:id"), {"id": existing}
    ).scalar_one() == "ACTIVE"
