from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.client_diagnostics import ClientDiagnosticsService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

ENTRY = {"time": "2026-10-05T09:00:00Z", "step": "bootstrap.cold-start", "detail": {"deviceType": "android"}}


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
    email = f"diag.{user_id[:8]}@example.test"
    db.execute(text("INSERT INTO security.security_principals VALUES (:i,'USER',:e,'ACTIVE',:n,:n)"),
               {"i": user_id, "e": email, "n": now})
    db.execute(
        text("INSERT INTO security.users (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)"
             " VALUES (:i,'Test Phone',:e,'ACTIVE',:n,:n)"),
        {"i": user_id, "e": email, "n": now},
    )
    return user_id


def _send(service: ClientDiagnosticsService, user: str, device: str, entries: list[dict[str, object]]) -> bool:
    return service.accept(user_id=user, device_id=device, platform="android", app_version="1.4", entries=entries)


def _count(db: Session) -> int:
    return int(db.execute(text("SELECT count(*) FROM security.client_diagnostic_logs")).scalar_one())


def test_it_is_off_by_default_and_stores_nothing_while_off(session: Session) -> None:
    service = ClientDiagnosticsService(session)
    user = _user(session)
    assert service.enabled() is False
    before = _count(session)
    assert _send(service, user, "device-0001", [ENTRY]) is False
    assert _count(session) == before


def test_when_on_a_log_is_kept_listed_and_a_second_one_from_the_same_device_is_held_back(session: Session) -> None:
    service = ClientDiagnosticsService(session)
    admin, user = _user(session), _user(session)
    service.set_enabled(enabled=True, actor_user_id=admin, correlation_id="c1")
    assert service.enabled() is True
    assert _send(service, user, "device-0002", [ENTRY]) is True
    assert _send(service, user, "device-0002", [ENTRY]) is False
    mine = [log for log in service.listing() if log["deviceId"] == "device-0002"]
    assert len(mine) == 1 and mine[0]["person"] == "Test Phone" and mine[0]["entryCount"] == 1
    assert mine[0]["entries"][0]["step"] == "bootstrap.cold-start"
    audit = session.execute(
        text(
            "SELECT count(*) FROM security.admin_change_records"
            " WHERE operation_key='security.client_diagnostics.manage'"
        )
    ).scalar_one()
    assert audit >= 1


def test_empty_or_oversized_uploads_are_not_kept_and_old_logs_are_pruned(session: Session) -> None:
    service = ClientDiagnosticsService(session)
    admin, user = _user(session), _user(session)
    service.set_enabled(enabled=True, actor_user_id=admin, correlation_id="c2")
    assert _send(service, user, "device-0003", []) is False
    assert _send(service, user, "device-0003", [ENTRY] * 101) is False
    big = {"time": "t", "step": "s", "detail": {"blob": "x" * 50_000}}
    assert _send(service, user, "device-0003", [big]) is False
    session.execute(
        text(
            "INSERT INTO security.client_diagnostic_logs (user_id,device_id,entry_count,entries,received_at_utc)"
            " VALUES (CAST(:u AS uuid),'old-device-1',1,'[]'::jsonb, now() - interval '20 days')"
        ),
        {"u": user},
    )
    assert _send(service, user, "device-0004", [ENTRY]) is True
    assert not [log for log in service.listing() if log["deviceId"] == "old-device-1"]


def test_clearing_removes_every_log(session: Session) -> None:
    service = ClientDiagnosticsService(session)
    admin, user = _user(session), _user(session)
    service.set_enabled(enabled=True, actor_user_id=admin, correlation_id="c3")
    _send(service, user, "device-0005", [ENTRY])
    assert service.clear(actor_user_id=admin, correlation_id="c4") >= 1
    assert _count(session) == 0
