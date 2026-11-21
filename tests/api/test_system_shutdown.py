"""Verigence shut for the night: nobody but the listed Super Admins and Executives reaches the
database through Security (product owner, 21 Nov 2026; core/system_shutdown.py).

On the night of 20 Nov every tab left open renewed its sign-in here every 13 minutes and the
database never stopped. The engine in these tests fails if it is touched."""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from datetime import time as clock_time
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from verigence_security import platform_heartbeat
from verigence_security.api.dependencies import repository, token_service
from verigence_security.api.routes import access
from verigence_security.config import Settings, get_settings
from verigence_security.core import system_shutdown
from verigence_security.main import app
from verigence_security.services.token_service import HumanTokenClaims, ServiceTokenClaims, TokenService

IST = ZoneInfo("Asia/Kolkata")
NIGHT = (clock_time(0, 30), clock_time(8, 0))
ALL_DAY = (clock_time(0, 0), clock_time(23, 59, 59))
SUPER_ADMIN = "66da15cc-8cb9-4b03-afa7-df6d4fae1e20"
EXECUTIVE = "21863dc4-44e1-46d4-846a-9cdb915a58d7"
TEAM_LEAD = "d09199ba-eb20-4107-adfe-982414ae0dc0"
SESSION_ID = "33333333-3333-3333-3333-333333333333"
DEVICE_ID = "44444444-4444-4444-4444-444444444444"

client = TestClient(app, raise_server_exceptions=False)


def _ist(hour: int, minute: int = 0) -> datetime:
    return datetime(2026, 11, 22, hour, minute, tzinfo=IST).astimezone(UTC)


def _listed() -> system_shutdown.Openers:
    return system_shutdown.parse_openers(json.dumps([
        {"userId": SUPER_ADMIN, "emailSha256": system_shutdown.email_hash("Owner@Example.com")},
        {"userId": EXECUTIVE.upper(), "emailSha256": system_shutdown.email_hash(" exec@example.com ")},
    ]))


@pytest.fixture(scope="module")
def keys() -> Settings:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return Settings(
        app_env="dev",
        security_key_id="key-1",
        platform_admin_token_ttl_minutes=15,
        security_private_key_pem=private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
        security_public_key_pem=private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    )


class _NoDatabase:
    """Stands for the repository: reaching for its session is the failure."""

    @property
    def s(self) -> object:
        raise AssertionError("the database was asked while Verigence is shut")


@pytest.fixture
def shut(monkeypatch: pytest.MonkeyPatch, keys: Settings):
    """Shut now, with the list configured and a database that must not be touched."""
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", ALL_DAY)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "get_settings", lambda: keys)
    app.dependency_overrides.clear()
    app.dependency_overrides[get_settings] = lambda: keys
    app.dependency_overrides[repository] = lambda: _NoDatabase()
    app.dependency_overrides[token_service] = lambda: TokenService(keys)
    yield TokenService(keys)
    app.dependency_overrides.clear()


def _person(tokens: TokenService, user_id: str, *, minutes: int = 10) -> dict[str, str]:
    token = tokens.issue_human_token(HumanTokenClaims(
        user_id=user_id, expires_at=datetime.now(UTC) + timedelta(minutes=minutes),
        session_id=SESSION_ID, device_id=DEVICE_ID))
    return {"Authorization": f"Bearer {token}"}


def _refused(response) -> None:
    assert response.status_code == 403, response.text
    body = response.json()
    assert body["code"] == "SYSTEM_CLOSED"
    assert body["detail"].startswith("Verigence is closed until ")
    assert body["opensAtUtc"].endswith("Z")
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.headers["X-Correlation-ID"] == body["correlationId"]


# ── the clock, the list ─────────────────────────────────────────────────────
def test_shut_is_the_nights_sleep_and_only_with_a_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", NIGHT)
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    for at in (_ist(0, 30), _ist(3), _ist(7, 59)):
        assert system_shutdown.closed(at)
    for at in (_ist(0, 29), _ist(8, 0), _ist(14), _ist(23, 59)):
        assert not system_shutdown.closed(at)
    assert system_shutdown.opens_at(_ist(3)) == _ist(8)
    assert system_shutdown.opens_at(_ist(14)) is None
    message = "Verigence is closed until 8:00 am. It opens by itself at that time."
    assert system_shutdown.closed_message(_ist(3)) == message
    assert system_shutdown.status(_ist(3)) == {
        "closed": True, "opensAtUtc": "2026-11-22T02:30:00Z", "message": message}
    assert system_shutdown.status(_ist(14)) == {"closed": False, "opensAtUtc": None, "message": None}

    # No list: never shut, whatever the hour. Nor with the gate switched off, nor with no sleep window.
    monkeypatch.setattr(system_shutdown, "OPENERS", system_shutdown.Openers())
    assert not system_shutdown.closed(_ist(3))
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    monkeypatch.setattr(system_shutdown, "GATE_ON", False)
    assert not system_shutdown.closed(_ist(3))
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", None)
    assert not system_shutdown.closed(_ist(3))


def test_a_window_that_ends_in_the_evening_names_the_right_opening(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", (clock_time(22, 0), clock_time(7, 30)))
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    at = datetime(2026, 11, 21, 23, 0, tzinfo=IST).astimezone(UTC)
    assert system_shutdown.opens_at(at) == datetime(2026, 11, 22, 7, 30, tzinfo=IST).astimezone(UTC)
    assert system_shutdown.closed_message(at).startswith("Verigence is closed until 7:30 am.")


def test_the_list_holds_user_ids_and_email_hashes_and_an_unreadable_one_is_no_list() -> None:
    listed = _listed()
    assert listed.user_ids == {SUPER_ADMIN, EXECUTIVE}
    assert system_shutdown.email_hash(" OWNER@example.com") in listed.email_hashes
    assert "owner@example.com" not in json.dumps(sorted(listed.email_hashes))
    for raw in (None, "", "   ", "not json", '{"userId": "x"}', "[]", '[{"emailSha256": "ab"}]', "[3]"):
        assert not system_shutdown.parse_openers(raw)
    # An entry with a user id but a hash that is not one still lets that person's renewals through.
    partial = system_shutdown.parse_openers(json.dumps([{"userId": SUPER_ADMIN, "emailSha256": "nope"}]))
    assert partial.user_ids == {SUPER_ADMIN} and not partial.email_hashes


# ── a person's requests while shut ──────────────────────────────────────────
def test_a_tab_left_open_is_refused_from_memory(shut: TokenService) -> None:
    # Renewal, resume, and everything else a person's session asks: no database.
    _refused(client.post("/security/v1/auth/refresh", headers=_person(shut, TEAM_LEAD)))
    _refused(client.post("/security/v1/auth/resume", json={}))
    _refused(client.get("/security/v1/status/app-version"))
    _refused(client.get("/security/v1/me/night-control", headers=_person(shut, TEAM_LEAD)))
    # A token that has run out, or is not one, tells nothing about who asks.
    _refused(client.post("/security/v1/auth/refresh", headers=_person(shut, SUPER_ADMIN, minutes=-1)))
    _refused(client.post("/security/v1/auth/refresh", headers={"Authorization": "Bearer nonsense"}))
    _refused(client.post("/security/v1/auth/refresh", headers={"Authorization": "Basic c2V2YTp4"}))


def test_sign_in_is_refused_for_anyone_not_listed_before_anything_is_read_or_recorded(
        shut: TokenService, monkeypatch: pytest.MonkeyPatch) -> None:
    def no_record(*_: object, **__: object) -> None:
        raise AssertionError("a refused sign-in was recorded (a database write)")

    monkeypatch.setattr(access, "record_login_attempt", no_record)
    response = client.post(
        "/security/v1/auth/login", json={"identifier": "pc@example.com", "password": "safe-password-123"})
    assert response.status_code == 403, response.text
    assert response.json()["code"] == "SYSTEM_CLOSED"
    assert response.json()["detail"].startswith("Verigence is closed until ")


def test_a_listed_person_signs_in_and_renews_as_by_day(shut: TokenService, monkeypatch: pytest.MonkeyPatch) -> None:
    reached: list[str] = []

    class _Credentials:
        def __init__(self, settings: Settings, session: object | None = None) -> None:
            reached.append("sign-in")
            raise RuntimeError("as far as the database: enough for this test")

    monkeypatch.setattr(access, "ClerkCredentialService", _Credentials)
    app.dependency_overrides[repository] = lambda: SimpleNamespace(s=object())
    signed = client.post(
        "/security/v1/auth/login", json={"identifier": " Owner@Example.com", "password": "safe-password-123"})
    assert signed.status_code == 500 and reached == ["sign-in"]

    class _Actor:
        def __init__(self, session: object) -> None:
            reached.append("renewal")
            raise RuntimeError("as far as the database: enough for this test")

    monkeypatch.setattr(access, "HumanActorAuthenticationService", _Actor)
    for user in (SUPER_ADMIN, EXECUTIVE):
        assert client.post("/security/v1/auth/refresh", headers=_person(shut, user)).status_code == 500
    assert reached == ["sign-in", "renewal", "renewal"]


def test_services_and_the_always_open_paths_pass(shut: TokenService) -> None:
    assert client.get("/health/live").status_code == 200
    assert client.get("/.well-known/jwks.json").status_code == 200
    state = client.get("/security/v1/system/status")
    assert state.status_code == 200 and state.json()["closed"] is True and state.json()["opensAtUtc"]
    # A service's own token: the request goes on to its endpoint (which here fails on the missing database).
    service = shut.issue_service_token(ServiceTokenClaims(
        subject="audit-core", audience="security", expires_at=datetime.now(UTC) + timedelta(minutes=5)))
    passed = client.post("/security/v1/authorization/check", headers={"Authorization": f"Bearer {service}"}, json={})
    assert passed.status_code != 403 or passed.json().get("code") != "SYSTEM_CLOSED"
    # Asking for a machine token is a service's business too.
    asked = client.post(
        "/security/v1/service/token", data={"audience": "audit"}, headers={"Authorization": "Basic c2V2YTp4"})
    assert asked.status_code != 403 or asked.json().get("code") != "SYSTEM_CLOSED"


def test_open_by_day_and_with_no_list_nothing_changes(shut: TokenService, monkeypatch: pytest.MonkeyPatch) -> None:
    reached: list[str] = []

    class _Actor:
        def __init__(self, session: object) -> None:
            reached.append("renewal")
            raise RuntimeError("as far as the database: enough for this test")

    monkeypatch.setattr(access, "HumanActorAuthenticationService", _Actor)
    app.dependency_overrides[repository] = lambda: SimpleNamespace(s=object())
    # By day.
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", None)
    assert client.post("/security/v1/auth/refresh", headers=_person(shut, TEAM_LEAD)).status_code == 500
    assert client.get("/security/v1/system/status").json() == {"closed": False, "opensAtUtc": None, "message": None}
    # At night with no list configured.
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", ALL_DAY)
    monkeypatch.setattr(system_shutdown, "OPENERS", system_shutdown.Openers())
    assert client.post("/security/v1/auth/refresh", headers=_person(shut, TEAM_LEAD)).status_code == 500
    assert reached == ["renewal", "renewal"]
