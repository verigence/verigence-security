from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.dependencies import repository, token_service
from verigence_security.api.routes import human_remember
from verigence_security.config import Settings, get_settings
from verigence_security.main import app

client = TestClient(app, base_url="https://testserver")

USER_ID = "11111111-1111-1111-1111-111111111111"
SESSION_ID = "22222222-2222-2222-2222-222222222222"
DEVICE_ID = "33333333-3333-3333-3333-333333333333"


class _FakeTokens:
    def verify_human_token(self, token: str) -> dict[str, object]:
        assert token == "current-access"
        return {
            "sub": USER_ID,
            "session_id": SESSION_ID,
            "device_id": DEVICE_ID,
        }

    def issue_human_token(self, claims: object) -> str:
        assert claims.user_id == USER_ID
        assert claims.session_id == SESSION_ID
        assert claims.device_id == DEVICE_ID
        return "resumed-access"


class _FakeActorService:
    def __init__(self, session: object) -> None:
        _ = session

    def authenticate_user_id(self, user_id: str) -> object:
        assert user_id == USER_ID
        return SimpleNamespace(user_id=USER_ID, is_super_admin=False)


class _FakeObservationRepository:
    def __init__(self, session: object) -> None:
        _ = session

    def session_status(self, **kwargs: object) -> str | None:
        assert str(kwargs["user_id"]) == USER_ID
        assert str(kwargs["session_id"]) == SESSION_ID
        assert str(kwargs["device_id"]) == DEVICE_ID
        return "ACTIVE"


class _FakeRememberRepository:
    record: dict[str, object] | None = None

    def __init__(self, session: object) -> None:
        _ = session

    def replace_for_login(
        self,
        *,
        user_id: str,
        session_id: str,
        device_id: str,
        token_hash: str,
        expires_at: datetime,
        now: datetime,
    ) -> None:
        self.__class__.record = {
            "access_session_id": session_id,
            "user_id": user_id,
            "device_id": device_id,
            "token_hash": token_hash,
            "previous_token_hash": None,
            "status": "ACTIVE",
            "created_at_utc": now,
            "expires_at_utc": expires_at,
            "last_used_at_utc": now,
        }

    def lock_by_hash(self, *, token_hash: str) -> dict[str, object] | None:
        record = self.__class__.record
        if record is None:
            return None
        if token_hash not in {record["token_hash"], record["previous_token_hash"]}:
            return None
        return dict(record)

    def rotate(self, *, session_id: str, new_token_hash: str, now: datetime) -> None:
        record = self.__class__.record
        assert record is not None
        assert str(record["access_session_id"]) == session_id
        record["previous_token_hash"] = record["token_hash"]
        record["token_hash"] = new_token_hash
        record["last_used_at_utc"] = now

    def revoke_session(self, *, session_id: str, now: datetime) -> None:
        _ = now
        record = self.__class__.record
        assert record is not None
        assert str(record["access_session_id"]) == session_id
        record["status"] = "REVOKED"

    def revoke_by_hash(self, *, token_hash: str, now: datetime) -> None:
        _ = now
        record = self.__class__.record
        if record and token_hash in {record["token_hash"], record["previous_token_hash"]}:
            record["status"] = "REVOKED"


@pytest.fixture(autouse=True)
def _dependencies(monkeypatch: pytest.MonkeyPatch):
    _FakeRememberRepository.record = None
    app.dependency_overrides.clear()
    app.dependency_overrides[get_settings] = lambda: Settings(
        platform_admin_token_ttl_minutes=15,
        human_remember_session_ttl_days=30,
    )
    app.dependency_overrides[repository] = lambda: SimpleNamespace(s=object())
    app.dependency_overrides[token_service] = lambda: _FakeTokens()
    monkeypatch.setattr(human_remember, "HumanRememberRepository", _FakeRememberRepository)
    monkeypatch.setattr(human_remember, "HumanObservationRepository", _FakeObservationRepository)
    monkeypatch.setattr(human_remember, "HumanActorAuthenticationService", _FakeActorService)
    yield
    app.dependency_overrides.clear()


def _device(device_type: str) -> dict[str, object]:
    return {
        "deviceId": DEVICE_ID,
        "deviceType": device_type,
        "platform": "ANDROID" if device_type == "MOBILE" else "WINDOWS",
        "deviceName": "test-device",
    }


def test_normal_login_contract_does_not_gain_remember_fields() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/security/v1/auth/login"]["post"]
    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    component_name = request_schema["$ref"].rsplit("/", 1)[-1]
    component = schema["components"]["schemas"][component_name]
    assert set(component["properties"]) == {"identifier", "password", "device"}


def test_web_remember_uses_httponly_secure_cookie_and_never_exposes_secret() -> None:
    response = client.post(
        "/security/v1/auth/remember",
        headers={"Authorization": "Bearer current-access"},
        json={"device": _device("WEB")},
    )

    assert response.status_code == 200
    assert response.json()["remembered"] is True
    assert response.json()["rememberToken"] is None
    cookie = response.headers["set-cookie"].lower()
    assert "verigence_remember=" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite=strict" in cookie


def test_mobile_remember_returns_opaque_credential_then_rotates_on_resume() -> None:
    remember = client.post(
        "/security/v1/auth/remember",
        headers={"Authorization": "Bearer current-access"},
        json={"device": _device("MOBILE")},
    )
    assert remember.status_code == 200
    first = remember.json()["rememberToken"]
    assert isinstance(first, str) and len(first) >= 32
    record = _FakeRememberRepository.record
    assert record is not None
    assert record["token_hash"] == hashlib.sha256(first.encode()).hexdigest()

    resumed = client.post(
        "/security/v1/auth/resume",
        json={"device": _device("MOBILE"), "rememberToken": first},
    )
    assert resumed.status_code == 200
    assert resumed.json()["accessToken"] == "resumed-access"
    second = resumed.json()["rememberToken"]
    assert isinstance(second, str) and second != first
    assert record["previous_token_hash"] == hashlib.sha256(first.encode()).hexdigest()
    assert record["token_hash"] == hashlib.sha256(second.encode()).hexdigest()


def test_replaying_rotated_mobile_credential_revokes_remember_family() -> None:
    expires_at = datetime.now(UTC) + timedelta(days=30)
    first = "a" * 48
    first_hash = hashlib.sha256(first.encode()).hexdigest()
    _FakeRememberRepository.record = {
        "access_session_id": SESSION_ID,
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "token_hash": hashlib.sha256(("b" * 48).encode()).hexdigest(),
        "previous_token_hash": first_hash,
        "status": "ACTIVE",
        "created_at_utc": datetime.now(UTC),
        "expires_at_utc": expires_at,
        "last_used_at_utc": datetime.now(UTC),
    }

    replay = client.post(
        "/security/v1/auth/resume",
        json={"device": _device("MOBILE"), "rememberToken": first},
    )
    assert replay.status_code in {401, 403}
    assert _FakeRememberRepository.record["status"] == "REVOKED"


def test_resume_rejects_different_device() -> None:
    token = "c" * 48
    _FakeRememberRepository.record = {
        "access_session_id": SESSION_ID,
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "previous_token_hash": None,
        "status": "ACTIVE",
        "created_at_utc": datetime.now(UTC),
        "expires_at_utc": datetime.now(UTC) + timedelta(days=30),
        "last_used_at_utc": datetime.now(UTC),
    }
    wrong = _device("MOBILE")
    wrong["deviceId"] = "44444444-4444-4444-4444-444444444444"

    response = client.post(
        "/security/v1/auth/resume",
        json={"device": wrong, "rememberToken": token},
    )
    assert response.status_code in {401, 403}


def test_logout_revokes_remember_credential() -> None:
    token = "d" * 48
    _FakeRememberRepository.record = {
        "access_session_id": SESSION_ID,
        "user_id": USER_ID,
        "device_id": DEVICE_ID,
        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "previous_token_hash": None,
        "status": "ACTIVE",
        "created_at_utc": datetime.now(UTC),
        "expires_at_utc": datetime.now(UTC) + timedelta(days=30),
        "last_used_at_utc": datetime.now(UTC),
    }

    response = client.post(
        "/security/v1/auth/logout",
        json={"device": _device("MOBILE"), "rememberToken": token},
    )
    assert response.status_code == 204
    assert _FakeRememberRepository.record["status"] == "REVOKED"
