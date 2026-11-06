"""Night control against PostgreSQL (product owner, 6 Nov 2026)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime, time
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.night_control import NightControlService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

NIGHT = datetime(2026, 11, 6, 16, 0, tzinfo=UTC)  # 21:30 IST
DAY = datetime(2026, 11, 6, 6, 0, tzinfo=UTC)  # 11:30 IST


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
        db.execute(text("DELETE FROM security.night_access_grants"))
        db.execute(
            text(
                "UPDATE security.night_control_features SET enabled = true,"
                " starts_local = '20:00', ends_local = '08:30'"
            )
        )
        yield db
    finally:
        db.close()
        outer.rollback()
        conn.close()
        engine.dispose()


def _user(db: Session, role: str | None = None) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    db.execute(
        text(
            "INSERT INTO security.users (user_id, display_name, primary_email, status, created_at_utc,"
            " updated_at_utc) VALUES (:i, 'Night Person', :e, 'ACTIVE', :n, :n)"
        ),
        {"i": user_id, "e": f"night.{user_id[:8]}@example.test", "n": now},
    )
    if role == "SuperAdmin":
        db.execute(
            text(
                "INSERT INTO security.user_admin_role_assignments (assignment_id, user_id, role_key, scope_type,"
                " status, assigned_at_utc) VALUES (:a, :u, 'SuperAdmin', 'PLATFORM', 'ACTIVE', :n)"
            ),
            {"a": str(uuid4()), "u": user_id, "n": now},
        )
    elif role:
        db.execute(
            text(
                "INSERT INTO security.user_tenant_operating_roles (assignment_id, user_id, tenant_id, role_key,"
                " status, assigned_by_user_id, assigned_at_utc) VALUES (:a, :u, :t, :r, 'ACTIVE', :u, :n)"
            ),
            {"a": str(uuid4()), "u": user_id, "t": str(uuid4()), "r": role, "n": now},
        )
    return user_id


def test_everyone_is_blocked_at_night_except_superadmin_and_executive(session: Session) -> None:
    service = NightControlService(session)
    pc, tl = _user(session, "PC"), _user(session, "TL")
    admin, executive = _user(session, "SuperAdmin"), _user(session, "Executive")
    for person in (pc, tl):
        for feature in ("JOURNEY_360", "FILE_DOWNLOAD"):
            decision = service.check(person, feature, now=NIGHT)
            assert decision["blocked"] and decision["reasonCode"] == "NIGHT_MODE"
            assert decision["message"] == "Night Mode On"
            assert not service.check(person, feature, now=DAY)["blocked"]
    assert service.check(admin, "JOURNEY_360", now=NIGHT)["allowedBy"] == "SUPER_ADMIN"
    assert service.check(executive, "FILE_DOWNLOAD", now=NIGHT)["allowedBy"] == "EXECUTIVE"
    assert not service.check(executive, "FILE_DOWNLOAD", now=NIGHT)["blocked"]
    # a feature Security does not control is never blocked
    assert not service.check(pc, "SOMETHING_ELSE", now=NIGHT)["blocked"]
    state = service.state(pc, now=NIGHT)
    assert state["nightModeOn"] and state["exempt"] is None
    assert not service.state(pc, now=DAY)["nightModeOn"]


def test_superadmin_gives_access_per_feature_or_to_all_until_removed(session: Session) -> None:
    service = NightControlService(session)
    admin, pc, tl = _user(session, "SuperAdmin"), _user(session, "PC"), _user(session, "TL")

    one = service.grant(
        user_id=pc, feature_key="JOURNEY_360", note="Month-end closing", actor_user_id=admin, correlation_id="c1"
    )
    assert not service.check(pc, "JOURNEY_360", now=NIGHT)["blocked"]
    assert service.check(pc, "JOURNEY_360", now=NIGHT)["allowedBy"] == "GRANT"
    assert service.check(pc, "FILE_DOWNLOAD", now=NIGHT)["blocked"]  # only the feature given

    service.grant(user_id=tl, feature_key=None, note="Audit visit", actor_user_id=admin, correlation_id="c2")
    assert not service.check(tl, "JOURNEY_360", now=NIGHT)["blocked"]
    assert not service.check(tl, "FILE_DOWNLOAD", now=NIGHT)["blocked"]

    with pytest.raises(FileExistsError):
        service.grant(user_id=pc, feature_key="JOURNEY_360", note="again", actor_user_id=admin, correlation_id="c3")
    with pytest.raises(LookupError):
        service.grant(user_id=str(uuid4()), feature_key=None, note="nobody", actor_user_id=admin, correlation_id="c4")

    overview = service.overview(now=NIGHT)
    assert {g["userId"] for g in overview["grants"]} == {pc, tl}
    assert all(f["active"] for f in overview["features"])

    assert service.revoke(grant_id=one["grantId"], note="Closing done", actor_user_id=admin, correlation_id="c5")
    assert not service.revoke(grant_id=one["grantId"], note="again", actor_user_id=admin, correlation_id="c6")
    assert service.check(pc, "JOURNEY_360", now=NIGHT)["blocked"]
    # each change is recorded
    ops = (
        session.execute(
            text("SELECT operation_key FROM security.admin_change_records WHERE actor_user_id = CAST(:a AS uuid)"),
            {"a": admin},
        )
        .scalars()
        .all()
    )
    assert sorted(ops) == sorted(["security.night_control.grant"] * 2 + ["security.night_control.revoke"])


def test_superadmin_can_switch_a_feature_off_or_move_its_hours(session: Session) -> None:
    service = NightControlService(session)
    admin, pc = _user(session, "SuperAdmin"), _user(session, "PC")
    service.set_feature(
        feature_key="FILE_DOWNLOAD",
        enabled=False,
        starts=time(20, 0),
        ends=time(8, 30),
        actor_user_id=admin,
        correlation_id="c1",
    )
    assert not service.check(pc, "FILE_DOWNLOAD", now=NIGHT)["blocked"]
    assert service.check(pc, "JOURNEY_360", now=NIGHT)["blocked"]
    service.set_feature(
        feature_key="JOURNEY_360",
        enabled=True,
        starts=time(22, 0),
        ends=time(6, 0),
        actor_user_id=admin,
        correlation_id="c2",
    )
    assert not service.check(pc, "JOURNEY_360", now=NIGHT)["blocked"]  # 21:30 is before 22:00 now
    with pytest.raises(ValueError):
        service.set_feature(
            feature_key="JOURNEY_360",
            enabled=True,
            starts=time(9, 0),
            ends=time(9, 0),
            actor_user_id=admin,
            correlation_id="c3",
        )
    with pytest.raises(LookupError):
        service.set_feature(
            feature_key="NOPE",
            enabled=True,
            starts=time(20, 0),
            ends=time(8, 30),
            actor_user_id=admin,
            correlation_id="c4",
        )
