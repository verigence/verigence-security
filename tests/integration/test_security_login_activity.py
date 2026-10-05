from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.login_activity import LoginActivityService

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


def _user(db: Session, name: str) -> tuple[str, str]:
    user_id = str(uuid4())
    now = datetime.now(UTC)
    email = f"{name}.{user_id[:8]}@example.test"
    db.execute(text("INSERT INTO security.security_principals VALUES (:i,'USER',:e,'ACTIVE',:n,:n)"),
               {"i": user_id, "e": email, "n": now})
    db.execute(
        text("INSERT INTO security.users (user_id,display_name,primary_email,status,created_at_utc,updated_at_utc)"
             " VALUES (:i,:d,:e,'ACTIVE',:n,:n)"),
        {"i": user_id, "d": name, "e": email, "n": now},
    )
    return user_id, email


def _attempt(db: Session, email: str, outcome: str, *, user: str | None = None, reason: str | None = None,
             device: str | None = None, platform: str | None = None, version: str | None = None) -> None:
    db.execute(
        text("INSERT INTO security.login_attempts (identifier,user_id,outcome,reason,device_type,platform,app_version)"
             " VALUES (:e,CAST(:u AS uuid),:o,:r,:d,:p,:v)"),
        {"e": email, "u": user, "o": outcome, "r": reason, "d": device, "p": platform, "v": version},
    )


def _row(report: dict, user_id: str) -> dict:
    return next(p for p in report["people"] if p["userId"] == user_id)


def test_the_report_tells_each_person_apart(session: Session) -> None:
    service = LoginActivityService(session)
    app_user, app_email = _user(session, "appuser")
    got_apk, apk_email = _user(session, "gotapk")
    web_user, web_email = _user(session, "webonly")
    failed_user, failed_email = _user(session, "failedonly")
    silent_user, _ = _user(session, "silent")

    _attempt(session, app_email, "FAILED", reason="clerk_password_verification_rejected")
    _attempt(session, app_email, "SUCCESS", user=app_user, device="WEB", platform="WINDOWS")
    _attempt(session, app_email, "SUCCESS", user=app_user, device="MOBILE", platform="ANDROID", version="1.4")
    service.record_download(user_id=got_apk, app_version="1.4", source_ip="1.2.3.4")
    _attempt(session, apk_email, "SUCCESS", user=got_apk, device="WEB", platform="MACOS")
    _attempt(session, web_email, "SUCCESS", user=web_user, device="WEB", platform="LINUX")
    # A failed attempt has no user id: it is matched by the e-mail address typed.
    _attempt(session, failed_email.upper().lower(), "FAILED", reason="security_identity_resolution_failed")
    _attempt(session, failed_email, "FAILED", reason="clerk_password_verification_rejected")
    _attempt(session, "stranger@example.test", "FAILED", reason="security_identity_resolution_failed")

    report = service.report()

    app_row = _row(report, app_user)
    assert (app_row["state"], app_row["loginsOk"], app_row["loginsFailed"]) == ("APP_SIGNED_IN", 2, 1)
    assert (app_row["appLogins"], app_row["webLogins"], app_row["appVersion"]) == (1, 1, "1.4")
    assert _row(report, got_apk)["state"] == "DOWNLOADED"
    assert _row(report, got_apk)["downloads"] == 1
    assert _row(report, web_user)["state"] == "WEB_ONLY"
    failed = _row(report, failed_user)
    assert (failed["state"], failed["loginsFailed"], failed["lastOutcome"]) == ("TRIED_FAILED", 2, "FAILED")
    assert failed["lastReason"] == "clerk_password_verification_rejected"
    assert _row(report, silent_user)["state"] == "NOT_TRIED"
    assert [u["identifier"] for u in report["unknown"]] == ["stranger@example.test"]
