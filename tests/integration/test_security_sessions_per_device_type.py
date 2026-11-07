"""One signed-in session and one remembered sign-in per user PER DEVICE TYPE, against PostgreSQL
(product owner, 7 Nov 2026): a phone (MOBILE) and a PC browser (WEB) may both stay signed in; a new
phone replaces the previous phone, a new browser the previous browser."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.repositories.human_observation_repository import HumanObservationRepository
from verigence_security.repositories.human_remember_repository import HumanRememberRepository

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url.removeprefix(prefix)
    return url


@pytest.fixture
def session() -> Iterator[Session]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
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


def _user(db: Session) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    db.execute(
        text(
            "INSERT INTO security.users (user_id, display_name, primary_email, status, created_at_utc,"
            " updated_at_utc) VALUES (:i, 'Device Person', :e, 'ACTIVE', :n, :n)"
        ),
        {"i": user_id, "e": f"device.{user_id[:8]}@example.test", "n": now},
    )
    return user_id


def _sign_in(db: Session, user_id: str, device_id: UUID, device_type: str, now: datetime) -> tuple[UUID, dict]:
    """What a sign-in does in Security: the remembered credential, then the session observation."""
    session_id = uuid4()
    HumanRememberRepository(db).replace_for_login(
        user_id=user_id,
        session_id=str(session_id),
        device_id=str(device_id),
        device_type=device_type,
        token_hash=uuid4().hex + uuid4().hex,
        expires_at=now + timedelta(days=30),
        now=now,
    )
    registration = HumanObservationRepository(db).register_observation_session(
        user_id=user_id,
        session_id=session_id,
        device_id=device_id,
        device_type=device_type,
        platform="ANDROID" if device_type == "MOBILE" else "WINDOWS",
        device_name=None,
        device_model=None,
        os_version=None,
        browser_name="Capacitor WebView" if device_type == "MOBILE" else "Chrome",
        browser_version=None,
        app_version="1.6.4" if device_type == "MOBILE" else None,
        source_ip="127.0.0.1",
        token_expires_at=now + timedelta(minutes=15),
        now=now,
    )
    return session_id, registration


def _session_status(db: Session, user_id: str, session_id: UUID, device_id: UUID) -> str | None:
    return HumanObservationRepository(db).session_status(user_id=user_id, session_id=session_id, device_id=device_id)


def _remember_status(db: Session, session_id: UUID) -> str:
    return str(
        db.execute(
            text("SELECT status FROM security.human_remember_sessions WHERE access_session_id=:s"),
            {"s": str(session_id)},
        ).scalar_one()
    )


def test_a_pc_sign_in_does_not_end_the_phone(session: Session) -> None:
    user_id = _user(session)
    phone, pc = uuid4(), uuid4()
    now = datetime.now(UTC)

    phone_session, _ = _sign_in(session, user_id, phone, "MOBILE", now)
    pc_session, registration = _sign_in(session, user_id, pc, "WEB", now + timedelta(minutes=1))

    assert registration["previous_session_superseded"] is False
    assert _session_status(session, user_id, phone_session, phone) == "ACTIVE"
    assert _session_status(session, user_id, pc_session, pc) == "ACTIVE"
    assert _remember_status(session, phone_session) == "ACTIVE"
    assert _remember_status(session, pc_session) == "ACTIVE"

    # ... and the phone signing in again does not end the PC either.
    phone_again, _ = _sign_in(session, user_id, phone, "MOBILE", now + timedelta(minutes=2))
    assert _session_status(session, user_id, pc_session, pc) == "ACTIVE"
    assert _remember_status(session, pc_session) == "ACTIVE"
    # the phone's own earlier session is replaced by its new one
    assert _session_status(session, user_id, phone_session, phone) == "SUPERSEDED"
    assert _remember_status(session, phone_session) == "REVOKED"
    assert _remember_status(session, phone_again) == "ACTIVE"


def test_a_second_phone_replaces_the_first_phone(session: Session) -> None:
    user_id = _user(session)
    first_phone, second_phone, pc = uuid4(), uuid4(), uuid4()
    now = datetime.now(UTC)

    first_session, _ = _sign_in(session, user_id, first_phone, "MOBILE", now)
    pc_session, _ = _sign_in(session, user_id, pc, "WEB", now + timedelta(minutes=1))
    second_session, registration = _sign_in(session, user_id, second_phone, "MOBILE", now + timedelta(minutes=2))

    assert registration["previous_session_superseded"] is True
    assert registration["previous_session_different_device"] is True
    assert _session_status(session, user_id, first_session, first_phone) == "SUPERSEDED"
    assert _remember_status(session, first_session) == "REVOKED"
    assert _session_status(session, user_id, second_session, second_phone) == "ACTIVE"
    assert _remember_status(session, second_session) == "ACTIVE"
    assert _session_status(session, user_id, pc_session, pc) == "ACTIVE"
    assert _remember_status(session, pc_session) == "ACTIVE"


def test_a_second_browser_replaces_the_first_browser(session: Session) -> None:
    user_id = _user(session)
    phone, first_pc, second_pc = uuid4(), uuid4(), uuid4()
    now = datetime.now(UTC)

    phone_session, _ = _sign_in(session, user_id, phone, "MOBILE", now)
    first_pc_session, _ = _sign_in(session, user_id, first_pc, "WEB", now + timedelta(minutes=1))
    second_pc_session, _ = _sign_in(session, user_id, second_pc, "WEB", now + timedelta(minutes=2))

    assert _session_status(session, user_id, first_pc_session, first_pc) == "SUPERSEDED"
    assert _remember_status(session, first_pc_session) == "REVOKED"
    assert _session_status(session, user_id, second_pc_session, second_pc) == "ACTIVE"
    assert _session_status(session, user_id, phone_session, phone) == "ACTIVE"
    assert _remember_status(session, phone_session) == "ACTIVE"


def test_the_database_allows_one_active_session_per_device_type_only(session: Session) -> None:
    user_id = _user(session)
    phone = uuid4()
    now = datetime.now(UTC)
    first, _ = _sign_in(session, user_id, phone, "MOBILE", now)
    with pytest.raises(IntegrityError), session.begin_nested():
        session.execute(
            text(
                "INSERT INTO security.human_access_sessions (access_session_id, user_id, device_id, device_type,"
                " status, started_at_utc, token_expires_at_utc, last_seen_at_utc)"
                " VALUES (:s, :u, :d, 'MOBILE', 'ACTIVE', :n, :e, :n)"
            ),
            {"s": str(uuid4()), "u": user_id, "d": str(phone), "n": now, "e": now + timedelta(minutes=15)},
        )
    with pytest.raises(IntegrityError), session.begin_nested():
        session.execute(
            text(
                "INSERT INTO security.human_remember_sessions (access_session_id, user_id, device_id, device_type,"
                " token_hash, status, created_at_utc, expires_at_utc, last_used_at_utc)"
                " VALUES (:s, :u, :d, 'MOBILE', :h, 'ACTIVE', :n, :e, :n)"
            ),
            {"s": str(uuid4()), "u": user_id, "d": str(phone), "h": "f" * 64, "n": now,
             "e": now + timedelta(days=30)},
        )
    # an ACTIVE remembered sign-in must always say which device type it belongs to
    with pytest.raises(IntegrityError), session.begin_nested():
        session.execute(
            text(
                "INSERT INTO security.human_remember_sessions (access_session_id, user_id, device_id,"
                " token_hash, status, created_at_utc, expires_at_utc, last_used_at_utc)"
                " VALUES (:s, :u, :d, :h, 'ACTIVE', :n, :e, :n)"
            ),
            {"s": str(uuid4()), "u": user_id, "d": str(uuid4()), "h": "e" * 64, "n": now,
             "e": now + timedelta(days=30)},
        )
    assert _session_status(session, user_id, first, phone) == "ACTIVE"
