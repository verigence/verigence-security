from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.feature_access import FeatureAccessService

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
        # Other tests may have left settings behind; start from a clean slate inside the rollback.
        db.execute(text("DELETE FROM security.feature_access"))
        yield db
    finally:
        db.close()
        outer.rollback()
        conn.close()
        engine.dispose()


def _user(db: Session) -> str:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    email = f"feat.{user_id[:8]}@example.test"
    db.execute(
        text("INSERT INTO security.security_principals VALUES (:i,'USER',:e,'ACTIVE',:n,:n)"),
        {"i": user_id, "e": email, "n": now},
    )
    db.execute(
        text(
            "INSERT INTO security.users (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)"
            " VALUES (:i,'Feature Person',:e,'ACTIVE',:n,:n)"
        ),
        {"i": user_id, "e": email, "n": now},
    )
    return user_id


def test_hidden_until_switched_on_and_a_persons_own_choice_wins(session: Session) -> None:
    service = FeatureAccessService(session)
    admin, person, other = _user(session), _user(session), _user(session)
    assert service.resolve(user_id=person, is_super_admin=False) == {"AUDIT": False, "ANALYTICS": False}

    service.set_person(feature_key="AUDIT", user_id=person, enabled=True, actor_user_id=admin, correlation_id="c1")
    assert service.resolve(user_id=person, is_super_admin=False)["AUDIT"] is True
    assert service.resolve(user_id=other, is_super_admin=False)["AUDIT"] is False

    service.set_everyone(feature_key="ANALYTICS", enabled=True, actor_user_id=admin, correlation_id="c2")
    assert service.resolve(user_id=other, is_super_admin=False)["ANALYTICS"] is True
    service.set_person(feature_key="ANALYTICS", user_id=other, enabled=False, actor_user_id=admin, correlation_id="c3")
    assert service.resolve(user_id=other, is_super_admin=False)["ANALYTICS"] is False  # own choice wins
    service.set_person(feature_key="ANALYTICS", user_id=other, enabled=None, actor_user_id=admin, correlation_id="c4")
    assert service.resolve(user_id=other, is_super_admin=False)["ANALYTICS"] is True  # back to everyone

    assert service.resolve(user_id=other, is_super_admin=True) == {"AUDIT": True, "ANALYTICS": True}


def test_overview_lists_the_people_set_on_their_own_and_changes_are_recorded(session: Session) -> None:
    service = FeatureAccessService(session)
    admin, person = _user(session), _user(session)
    service.set_person(feature_key="AUDIT", user_id=person, enabled=True, actor_user_id=admin, correlation_id="c5")
    service.set_everyone(feature_key="AUDIT", enabled=False, actor_user_id=admin, correlation_id="c6")
    audit = {f["featureKey"]: f for f in service.overview()}["AUDIT"]
    assert audit["everyone"] is False
    assert [(p["userId"], p["enabled"]) for p in audit["people"]] == [(person, True)]  # type: ignore[index]
    changes = session.execute(
        text(
            "SELECT count(*) FROM security.admin_change_records WHERE operation_key='security.feature_access.manage'"
            " AND actor_user_id=CAST(:a AS uuid)"
        ),
        {"a": admin},
    ).scalar_one()
    assert changes == 2


def test_unknown_feature_and_inactive_person_are_refused(session: Session) -> None:
    service = FeatureAccessService(session)
    admin = _user(session)
    with pytest.raises(ValueError):
        service.set_everyone(feature_key="PAYROLL", enabled=True, actor_user_id=admin, correlation_id="c7")
    with pytest.raises(ValueError):
        service.set_person(
            feature_key="AUDIT", user_id=str(uuid4()), enabled=True, actor_user_id=admin, correlation_id="c8"
        )
