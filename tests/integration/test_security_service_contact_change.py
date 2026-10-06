from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendError
from verigence_security.services.service_contact_change import ContactConflict, ServiceContactChange
from verigence_security.services.v2_platform_user_create import InvalidUserInput, V2PlatformUserCreateService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL is required")


def _url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url.removeprefix(prefix)
    return url


class _Clerk:
    def __init__(self, fail_replace: bool = False) -> None:
        self.fail_replace = fail_replace
        self.events: list[tuple[str, str]] = []
        self.primary: dict[str, str] = {}

    def create_user(self, *, first_name: str, last_name: str, email: str, password: str) -> str:
        subject = f"user_{uuid4().hex}"
        self.primary[subject] = email
        return subject

    def delete_user(self, clerk_user_id: str) -> None:
        pass

    def replace_primary_email(self, subject: str, email: str) -> str | None:
        if self.fail_replace:
            raise ClerkBackendError("provider down", status_code=503)
        previous = self.primary.get(subject)
        self.primary[subject] = email
        self.events.append(("replace", email))
        return previous

    def remove_other_emails(self, subject: str, keep: str) -> int:
        self.events.append(("remove", keep))
        return 1


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


def _integration(db: Session) -> str:
    principal_id = str(uuid4())
    key = f"hrmgmt-{principal_id[:8]}"
    db.execute(
        text("INSERT INTO security.security_principals VALUES (:id,'SERVICE_INTEGRATION',:name,'ACTIVE',now(),now())"),
        {"id": principal_id, "name": key},
    )
    db.execute(
        text(
            "INSERT INTO security.service_integrations (principal_id,integration_key,created_at_utc)"
            " VALUES (:id,:k,now())"
        ),
        {"id": principal_id, "k": key},
    )
    return principal_id


def _mobile() -> str:
    return "9" + str(uuid4().int)[:9]


def _user(db: Session, clerk: _Clerk, principal: str, *, email: str | None = None, mobile: str | None = None):
    return V2PlatformUserCreateService(db).create_for_service(
        first_name="Asha",
        last_name="Rao",
        email=email or f"old.{uuid4().hex[:8]}@example.test",
        mobile=mobile or _mobile(),
        password="not-stored",
        service_principal_id=principal,
        service_integration_key="hrmgmt",
        correlation_id=str(uuid4()),
        clerk=clerk,
    )


def _change(db: Session, clerk: _Clerk, principal: str, user_id: str, **kw):
    return ServiceContactChange(db).change(
        user_id=user_id,
        email=kw.get("email"),
        mobile=kw.get("mobile"),
        principal_id=principal,
        integration_key="hrmgmt",
        correlation_id=str(uuid4()),
        clerk=clerk,  # type: ignore[arg-type]
    )


def _row(db: Session, user_id: str):
    return db.execute(
        text(
            "SELECT u.primary_email,u.primary_mobile,u.status,p.principal_name,e.provider_subject"
            " FROM security.users u JOIN security.security_principals p ON p.principal_id=u.user_id"
            " JOIN security.external_identities e ON e.user_id=u.user_id WHERE u.user_id=:id"
        ),
        {"id": user_id},
    ).one()


def test_the_email_is_replaced_on_the_same_user_and_the_same_provider_account(session: Session) -> None:
    principal, clerk = _integration(session), _Clerk()
    created = _user(session, clerk, principal)
    new = f"new.{uuid4().hex[:8]}@example.test"
    done = _change(session, clerk, principal, created.user_id, email=new.upper())
    assert done.email_changed and not done.mobile_changed and done.old_email_removed
    row = _row(session, created.user_id)
    assert row[0] == new and row[3] == new and row[2] == "ACTIVE"
    assert row[4] == created.clerk_subject  # same provider account, same user id
    assert clerk.events == [("replace", new), ("remove", new)]  # the old one is removed last
    event = session.execute(
        text(
            "SELECT payload_json::text FROM security.security_events"
            " WHERE event_type='SERVICE_USER_CONTACT_CHANGE' AND entity_id=:id"
        ),
        {"id": created.user_id},
    ).scalar_one()
    assert new in event and "password" not in event.lower()


def test_a_mobile_only_change_never_calls_the_provider(session: Session) -> None:
    principal, clerk = _integration(session), _Clerk()
    created = _user(session, clerk, principal)
    clerk.events.clear()
    mobile = _mobile()
    done = _change(session, clerk, principal, created.user_id, mobile=mobile)
    assert done.mobile_changed and not done.email_changed
    assert _row(session, created.user_id)[1] == f"+91{mobile}"
    assert clerk.events == []


def test_an_email_or_mobile_of_another_user_is_refused_before_anything_changes(session: Session) -> None:
    principal, clerk = _integration(session), _Clerk()
    mine = _user(session, clerk, principal)
    other = _user(session, clerk, principal)
    other_row = _row(session, other.user_id)
    clerk.events.clear()
    with pytest.raises(ContactConflict):
        _change(session, clerk, principal, mine.user_id, email=other_row[0])
    with pytest.raises(ContactConflict):
        _change(session, clerk, principal, mine.user_id, mobile=other_row[1])
    assert clerk.events == []


def test_when_the_provider_fails_security_is_not_changed(session: Session) -> None:
    principal = _integration(session)
    created = _user(session, _Clerk(), principal)
    before = _row(session, created.user_id)
    with pytest.raises(ClerkBackendError):
        _change(session, _Clerk(fail_replace=True), principal, created.user_id, email="x@example.test")
    assert _row(session, created.user_id)[:2] == before[:2]


def test_when_security_cannot_save_the_provider_is_put_back(session: Session, monkeypatch: pytest.MonkeyPatch) -> None:
    principal, clerk = _integration(session), _Clerk()
    created = _user(session, clerk, principal)
    old = _row(session, created.user_id)[0]
    clerk.events.clear()

    def boom(self: ServiceContactChange, **kwargs: object) -> None:
        raise RuntimeError("database down")

    monkeypatch.setattr(ServiceContactChange, "_update", boom)
    with pytest.raises(RuntimeError):
        _change(session, clerk, principal, created.user_id, email="later@example.test")
    assert clerk.primary[created.clerk_subject] == old
    assert clerk.events == [("replace", "later@example.test"), ("replace", old), ("remove", old)]
    assert _row(session, created.user_id)[0] == old


def test_repeating_a_finished_request_changes_nothing_but_finishes_the_provider_side(session: Session) -> None:
    principal, clerk = _integration(session), _Clerk()
    created = _user(session, clerk, principal)
    new = f"new.{uuid4().hex[:8]}@example.test"
    _change(session, clerk, principal, created.user_id, email=new)
    again = _change(session, clerk, principal, created.user_id, email=new)
    assert not again.email_changed and again.old_email_removed
    assert _row(session, created.user_id)[0] == new


def test_bad_input_and_unknown_users(session: Session) -> None:
    principal, clerk = _integration(session), _Clerk()
    created = _user(session, clerk, principal)
    with pytest.raises(InvalidUserInput):
        _change(session, clerk, principal, created.user_id)
    with pytest.raises(InvalidUserInput):
        _change(session, clerk, principal, created.user_id, mobile="12345")
    with pytest.raises(InvalidUserInput):
        _change(session, clerk, principal, created.user_id, email="not-an-email")
    with pytest.raises(LookupError):
        _change(session, clerk, principal, str(uuid4()), email="a@example.test")
    with pytest.raises(LookupError):
        _change(session, clerk, principal, "not-a-uuid", email="a@example.test")
