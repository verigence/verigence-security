from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext
from verigence_security.services.v2_platform_user_create import (
    InvalidUserInput,
    V2PlatformUserCreateService,
)

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
        self.created: list[dict[str, str]] = []
        self.deleted: list[str] = []

    def create_user(self, *, first_name: str, last_name: str, email: str, password: str) -> str:
        self.created.append({"first_name": first_name, "last_name": last_name, "email": email})
        return f"user_created_{uuid4().hex}"

    def delete_user(self, clerk_user_id: str) -> None:
        self.deleted.append(clerk_user_id)


SUPER_ADMIN = HumanActorContext(
    user_id=str(uuid4()),
    clerk_subject="user_admin",
    admin_scopes=(AdminScope("SuperAdmin", "PLATFORM", None),),
)


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


def _create(db: Session, clerk: _FakeClerk, *, email: str, mobile: str, actor: HumanActorContext = SUPER_ADMIN):
    return V2PlatformUserCreateService(db).create(
        first_name="Sample",
        last_name="Person  Two",
        email=email,
        mobile=mobile,
        password="not-stored",
        actor=actor,
        correlation_id=str(uuid4()),
        clerk=clerk,
    )


def _seed_user(db: Session, *, email: str, mobile: str, status: str) -> None:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    db.execute(
        text(
            "INSERT INTO security.security_principals VALUES (:id,'USER',:email,'ACTIVE',:now,:now)"
        ),
        {"id": user_id, "email": email, "now": now},
    )
    db.execute(
        text(
            """
            INSERT INTO security.users
            (user_id,display_name,primary_email,primary_mobile,status,created_at_utc,updated_at_utc)
            VALUES (:id,'Existing',:email,:mobile,:status,:now,:now)
            """
        ),
        {"id": user_id, "email": email, "mobile": mobile, "status": status, "now": now},
    )
    db.commit()


def test_super_admin_creates_an_active_user_with_a_linked_clerk_identity(session: Session) -> None:
    clerk = _FakeClerk()
    email = f"Created.{uuid4().hex[:8]}@Example.test "
    created = _create(session, clerk, email=email, mobile="90000 00001")

    row = session.execute(
        text(
            """
            SELECT u.status,u.primary_email,u.primary_mobile,u.display_name,p.status AS principal_status,
                   e.provider_subject,e.status AS identity_status
            FROM security.users u
            JOIN security.security_principals p ON p.principal_id=u.user_id
            JOIN security.external_identities e ON e.user_id=u.user_id AND e.provider='CLERK'
            WHERE u.user_id=:id
            """
        ),
        {"id": created.user_id},
    ).mappings().one()
    assert row["status"] == "ACTIVE" and row["principal_status"] == "ACTIVE"
    assert row["identity_status"] == "ACTIVE" and row["provider_subject"] == created.clerk_subject
    assert row["primary_email"] == email.strip().lower()
    assert row["primary_mobile"] == "+919000000001"
    assert row["display_name"] == "Sample Person Two"
    assert clerk.created == [{"first_name": "Sample", "last_name": "Person Two", "email": email.strip().lower()}]

    audit = session.execute(
        text(
            """
            SELECT actor_user_id::text,after_state_json
            FROM security.admin_change_records
            WHERE operation_key='security.user.create' AND resource_id=:id
            """
        ),
        {"id": created.user_id},
    ).one()
    assert audit[0] == SUPER_ADMIN.user_id
    assert audit[1]["status"] == "ACTIVE"
    assert "password" not in str(audit[1]).lower()


def test_contacts_owned_by_active_or_pending_users_block_creation(session: Session) -> None:
    clerk = _FakeClerk()
    taken = f"taken.{uuid4().hex[:8]}@example.test"
    _seed_user(session, email=taken, mobile="+919000000002", status="ACTIVE")
    with pytest.raises(ValueError, match="active or suspended"):
        _create(session, clerk, email=taken, mobile="9000000003")

    pending = f"pending.{uuid4().hex[:8]}@example.test"
    _seed_user(session, email=pending, mobile="+919000000004", status="PENDING")
    with pytest.raises(ValueError, match="pending registration"):
        _create(session, clerk, email=f"other.{uuid4().hex[:8]}@example.test", mobile="9000000004")
    assert clerk.created == []


def test_invalid_input_and_non_super_admin_are_rejected_before_clerk(session: Session) -> None:
    clerk = _FakeClerk()
    with pytest.raises(InvalidUserInput, match="Indian mobile"):
        _create(session, clerk, email="x@example.test", mobile="12345")
    with pytest.raises(InvalidUserInput, match="email"):
        _create(session, clerk, email="not-an-email", mobile="9000000005")
    tenant_admin = HumanActorContext(
        user_id=str(uuid4()), clerk_subject="user_ta", admin_scopes=(AdminScope("TenantAdmin", "TENANT", "t1"),)
    )
    with pytest.raises(PermissionError):
        _create(session, clerk, email="x@example.test", mobile="9000000005", actor=tenant_admin)
    assert clerk.created == []


def test_a_failed_security_write_deletes_the_new_clerk_identity(
    session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    clerk = _FakeClerk()

    def _boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(V2PlatformUserCreateService, "_audit", _boom)
    with pytest.raises(RuntimeError):
        _create(session, clerk, email=f"rollback.{uuid4().hex[:8]}@example.test", mobile="9000000006")
    assert len(clerk.created) == 1 and len(clerk.deleted) == 1
