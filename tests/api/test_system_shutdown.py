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


@pytest.fixture(autouse=True)
def _the_clock_alone():
    system_shutdown.reset_switch()
    yield
    system_shutdown.reset_switch()


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
        "closed": True, "opensAtUtc": "2026-11-22T02:30:00Z", "message": message,
        "resting": True, "restUntilUtc": "2026-11-22T02:30:00Z",
        "hoursFromIst": "00:30", "hoursToIst": "08:00", "manual": None, "manualUntilUtc": None}
    assert system_shutdown.status(_ist(14)) == {
        "closed": False, "opensAtUtc": None, "message": None, "resting": False, "restUntilUtc": None,
        "hoursFromIst": "00:30", "hoursToIst": "08:00", "manual": None, "manualUntilUtc": None}

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
    state = client.get("/security/v1/system/status").json()
    assert (state["closed"], state["resting"], state["opensAtUtc"]) == (False, False, None)
    # At night with no list configured.
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", ALL_DAY)
    monkeypatch.setattr(system_shutdown, "OPENERS", system_shutdown.Openers())
    assert client.post("/security/v1/auth/refresh", headers=_person(shut, TEAM_LEAD)).status_code == 500
    assert reached == ["renewal", "renewal"]


# ── the switch: hours, Shut down now, Start now ─────────────────────────────
def _switch(**over: object) -> system_shutdown.Switch:
    return system_shutdown.Switch(**{"hours": NIGHT, "stored": True, **over})  # type: ignore[arg-type]


def test_shut_down_now_by_day_lasts_to_the_next_opening_and_start_now_ends_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    system_shutdown.set_switch(_switch())
    six_pm = _ist(18)
    assert not system_shutdown.resting(six_pm)

    system_shutdown.set_switch(system_shutdown.shut_now(SUPER_ADMIN, six_pm))
    next_morning = datetime(2026, 11, 23, 8, 0, tzinfo=IST).astimezone(UTC)
    for at in (six_pm, _ist(23, 59), next_morning - timedelta(minutes=1)):
        assert system_shutdown.resting(at) and system_shutdown.closed(at)
        assert system_shutdown.opens_at(at) == next_morning
    assert not system_shutdown.resting(next_morning)
    state = system_shutdown.status(six_pm)
    assert (state["manual"], state["restUntilUtc"]) == ("SHUT", "2026-11-23T02:30:00Z")
    assert state["message"].startswith("Verigence is closed until 8:00 am.")

    # Started again at 7 pm: running, and tonight's own hours still hold.
    seven_pm = _ist(19)
    system_shutdown.set_switch(system_shutdown.start_now(EXECUTIVE, seven_pm))
    assert not system_shutdown.resting(seven_pm)
    assert system_shutdown.status(seven_pm)["manual"] is None
    assert system_shutdown.resting(datetime(2026, 11, 23, 1, 0, tzinfo=IST).astimezone(UTC))


def test_start_now_at_night_opens_until_the_morning_and_no_longer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    system_shutdown.set_switch(_switch())
    three_am = _ist(3)
    assert system_shutdown.closed(three_am)
    system_shutdown.set_switch(system_shutdown.start_now(SUPER_ADMIN, three_am))
    for at in (three_am, _ist(7, 59)):
        assert not system_shutdown.resting(at) and not system_shutdown.closed(at)
    assert system_shutdown.status(three_am)["manual"] == "OPEN"
    # The override is over at 8:00; the next night is shut as every night.
    assert system_shutdown.status(_ist(9))["manual"] is None
    assert system_shutdown.resting(datetime(2026, 11, 23, 0, 30, tzinfo=IST).astimezone(UTC))
    # Shut down again the same night: shut to the morning.
    system_shutdown.set_switch(system_shutdown.shut_now(SUPER_ADMIN, _ist(4)))
    assert system_shutdown.opens_at(_ist(4)) == _ist(8)


def test_new_hours_take_effect_and_keep_a_manual_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    system_shutdown.set_switch(_switch())
    system_shutdown.set_switch(system_shutdown.with_hours(clock_time(22, 0), clock_time(7, 30), SUPER_ADMIN, _ist(12)))
    assert system_shutdown.resting(_ist(23)) and system_shutdown.resting(_ist(7, 29))
    assert not system_shutdown.resting(_ist(7, 30)) and not system_shutdown.resting(_ist(21, 59))
    assert system_shutdown.opens_at(_ist(23)) == datetime(2026, 11, 23, 7, 30, tzinfo=IST).astimezone(UTC)
    with pytest.raises(ValueError):
        system_shutdown.with_hours(clock_time(8, 0), clock_time(8, 0), SUPER_ADMIN)
    # A shutdown by hand that runs out inside the daily hours goes on to that morning's opening.
    system_shutdown.set_switch(_switch(manual="SHUT", manual_until=_ist(2)))
    assert system_shutdown.opens_at(_ist(1)) == _ist(8)


def test_until_the_state_is_read_the_clock_every_service_started_with_stands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_heartbeat, "SLEEP_WINDOW", (clock_time(1, 0), clock_time(6, 0)))
    assert system_shutdown.switch().hours == (clock_time(1, 0), clock_time(6, 0))
    assert system_shutdown.resting(_ist(2)) and not system_shutdown.resting(_ist(7))
    system_shutdown.set_switch(_switch())
    assert system_shutdown.resting(_ist(7))


class _Tab:
    """What the tab's endpoints keep and show, without a database."""

    def __init__(self) -> None:
        self.saved: list[tuple[str, system_shutdown.Switch]] = []
        self.committed = 0
        self.role: str | None = "SUPER_ADMIN"
        self.me: dict[str, str] = {}

    def commit(self) -> None:
        self.committed += 1


@pytest.fixture
def tab(monkeypatch: pytest.MonkeyPatch, keys: Settings):
    from verigence_security.api.platform_dependencies import platform_session
    from verigence_security.api.routes import system_shutdown as routes
    from verigence_security.api.v2_human_dependencies import security_human_actor

    state = _Tab()
    monkeypatch.setattr(system_shutdown, "GATE_ON", True)
    monkeypatch.setattr(system_shutdown, "OPENERS", _listed())
    system_shutdown.set_switch(_switch())
    monkeypatch.setattr(routes.store, "save", lambda session, switch, *, action: state.saved.append((action, switch)))
    monkeypatch.setattr(routes.store, "people", lambda session: [
        {"userId": SUPER_ADMIN, "name": "superadmin", "role": "Super Admin", "mayStart": True}])
    monkeypatch.setattr(routes.store, "last_change", lambda session: None)

    class _Roles:
        def __init__(self, session: object) -> None:
            pass

        def exempt_reason(self, user_id: str, *, is_super_admin: bool | None = None) -> str | None:
            return state.role

    monkeypatch.setattr(routes, "NightControlService", _Roles)
    # Once shut, the tab's own calls pass the gate as any listed person's do: by their token.
    monkeypatch.setattr(system_shutdown, "get_settings", lambda: keys)
    state.me = _person(TokenService(keys), SUPER_ADMIN)
    app.dependency_overrides.clear()
    app.dependency_overrides[platform_session] = lambda: state
    app.dependency_overrides[security_human_actor] = lambda: SimpleNamespace(user_id=SUPER_ADMIN, is_super_admin=True)
    yield state
    app.dependency_overrides.clear()


def test_the_tab_shuts_down_starts_and_sets_hours_for_a_super_admin_or_executive(tab: _Tab) -> None:
    base = "/security/v1/admin/system-shutdown"
    seen = client.get(base, headers=tab.me)
    assert seen.status_code == 200, seen.text
    assert seen.json()["gate"] is True and seen.json()["people"][0]["mayStart"] is True

    shut = client.post(f"{base}/shut-now", headers=tab.me)
    assert shut.status_code == 200 and shut.json()["manual"] == "SHUT" and shut.json()["resting"] is True
    assert system_shutdown.resting() and tab.saved[-1][0] == "SHUT_NOW" and tab.committed == 1
    # Shut: the tab without a listed person's token is refused like everything else.
    assert client.get(base).json()["code"] == "SYSTEM_CLOSED"

    tab.role = "EXECUTIVE"
    started = client.post(f"{base}/start-now", headers=tab.me)
    assert started.status_code == 200 and tab.saved[-1][0] == "START_NOW"
    assert system_shutdown.switch().manual != "SHUT"

    hours = client.put(f"{base}/hours", json={"fromIst": "22:00", "toIst": "07:30"}, headers=tab.me)
    assert hours.status_code == 200, hours.text
    assert (hours.json()["hoursFromIst"], hours.json()["hoursToIst"]) == ("22:00", "07:30")
    assert tab.saved[-1][0] == "HOURS 22:00-07:30"
    # Whatever the hour this test runs at, open it before the last two calls.
    client.post(f"{base}/start-now", headers=tab.me)
    assert client.put(f"{base}/hours", json={"fromIst": "08:00", "toIst": "08:00"}, headers=tab.me).status_code == 422
    assert client.put(f"{base}/hours", json={"fromIst": "8am", "toIst": "08:00"}, headers=tab.me).status_code == 422


def test_the_tab_is_for_nobody_else_and_a_change_that_cannot_be_kept_is_not_in_force(
        tab: _Tab, monkeypatch: pytest.MonkeyPatch) -> None:
    from verigence_security.api.routes import system_shutdown as routes

    base = "/security/v1/admin/system-shutdown"
    tab.role = None  # a Team Lead, a PC: no
    system_shutdown.set_switch(_switch(hours=None))  # running, whatever the hour this test runs at
    for call in (client.get(base, headers=tab.me), client.post(f"{base}/shut-now", headers=tab.me),
                 client.post(f"{base}/start-now", headers=tab.me),
                 client.put(f"{base}/hours", json={"fromIst": "22:00", "toIst": "07:30"}, headers=tab.me)):
        assert call.status_code == 403 and call.json()["code"] == "PERMISSION_DENIED"
    assert tab.saved == [] and not system_shutdown.switch().manual

    tab.role = "SUPER_ADMIN"

    def cannot_keep(session: object, switch: object, *, action: str) -> None:
        raise RuntimeError("the database refused")

    monkeypatch.setattr(routes.store, "save", cannot_keep)
    assert client.post(f"{base}/shut-now", headers=tab.me).status_code == 500
    assert not system_shutdown.switch().manual and not system_shutdown.resting(_ist(14))
