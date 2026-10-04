from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.announcements import AnnouncementService

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
        db.execute(text("DELETE FROM security.announcements"))
        db.execute(text("UPDATE security.announcement_settings SET quiet_hours=20"))
        yield db
    finally:
        db.close()
        outer.rollback()
        conn.close()
        engine.dispose()


def _user(db: Session) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    email = f"ann.{user_id[:8]}@example.test"
    db.execute(
        text("INSERT INTO security.security_principals VALUES (:i,'USER',:e,'ACTIVE',:n,:n)"),
        {"i": user_id, "e": email, "n": now},
    )
    db.execute(
        text(
            "INSERT INTO security.users (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)"
            " VALUES (:i,'Ann Person',:e,'ACTIVE',:n,:n)"
        ),
        {"i": user_id, "e": email, "n": now},
    )
    return user_id


def _make(service: AnnouncementService, admin: str, **over: object) -> str:
    args: dict[str, object] = {
        "kind": "NOTICE",
        "title": "Hello",
        "body": "A short note",
        "back_at": None,
        "starts_at": None,
        "ends_at": None,
        "audience": "EVERYONE",
        "people": [],
        "actor_user_id": admin,
        "correlation_id": "c",
    }
    args.update(over)
    return service.create(**args)  # type: ignore[arg-type]


def test_a_notice_is_shown_once_and_never_more_than_one_in_the_quiet_period(session: Session) -> None:
    service = AnnouncementService(session)
    admin, person = _user(session), _user(session)
    first = _make(service, admin, kind="WELCOME", title="Welcome")
    second = _make(service, admin, title="A second note")
    shown = service.next_for(user_id=person)
    assert shown is not None and shown["announcementId"] == first
    service.mark_seen(announcement_id=first, user_id=person)
    service.mark_seen(announcement_id=first, user_id=person)  # dismissing twice is harmless
    assert service.next_for(user_id=person) is None  # the second waits for the quiet period
    # the person's quiet period is over: the second is shown, the first never again
    session.execute(text("UPDATE security.announcement_seen SET seen_at_utc=CURRENT_TIMESTAMP-interval '21 hours'"))
    shown = service.next_for(user_id=person)
    assert shown is not None and shown["announcementId"] == second


def test_the_wait_between_notices_is_set_by_super_admin(session: Session) -> None:
    service = AnnouncementService(session)
    admin, person = _user(session), _user(session)
    a, b = _make(service, admin, title="One"), _make(service, admin, title="Two")
    service.set_quiet_hours(hours=0, actor_user_id=admin, correlation_id="c")
    assert service.quiet_hours() == 0
    service.mark_seen(announcement_id=a, user_id=person)
    nxt = service.next_for(user_id=person)
    assert nxt is not None and nxt["announcementId"] == b  # no wait, still once each
    service.set_quiet_hours(hours=48, actor_user_id=admin, correlation_id="c")
    assert service.next_for(user_id=person) is None
    with pytest.raises(ValueError):
        service.set_quiet_hours(hours=1000, actor_user_id=admin, correlation_id="c")


def test_audience_window_and_stopping(session: Session) -> None:
    service = AnnouncementService(session)
    admin, chosen, other = _user(session), _user(session), _user(session)
    only = _make(service, admin, audience="PEOPLE", people=[chosen], title="Just for you")
    assert service.next_for(user_id=other) is None
    assert service.next_for(user_id=chosen) is not None
    now = datetime.now(UTC)
    _make(service, admin, title="Later", starts_at=now + timedelta(days=1))
    _make(service, admin, title="Over", starts_at=now - timedelta(days=3), ends_at=now - timedelta(days=1))
    assert service.next_for(user_id=other) is None  # not started yet, or already over
    service.update(
        announcement_id=only,
        title=None,
        body=None,
        back_at=None,
        ends_at=None,
        active=False,
        people=None,
        actor_user_id=admin,
        correlation_id="c",
    )
    assert service.next_for(user_id=chosen) is None
    with pytest.raises(ValueError):
        _make(service, admin, audience="PEOPLE", people=[])


def test_maintenance_blocks_until_ended_and_only_one_can_run(session: Session) -> None:
    service = AnnouncementService(session)
    admin, person = _user(session), _user(session)
    assert service.maintenance() is None
    back = datetime.now(UTC) + timedelta(hours=2)
    m = _make(service, admin, kind="MAINTENANCE", title="Back soon", body="Upgrading", back_at=back)
    shown = service.maintenance()
    assert shown is not None and shown["title"] == "Back soon" and shown["backAt"] is not None
    assert service.next_for(user_id=person) is None  # maintenance is not a notice
    with pytest.raises(Exception):  # noqa: B017
        _make(service, admin, kind="MAINTENANCE", title="Another")
    session.rollback()
    with pytest.raises(ValueError):
        _make(service, admin, kind="MAINTENANCE", audience="PEOPLE", people=[person])
    service.update(
        announcement_id=m,
        title=None,
        body=None,
        back_at=None,
        ends_at=None,
        active=False,
        people=None,
        actor_user_id=admin,
        correlation_id="c",
    )
    assert service.maintenance() is None
