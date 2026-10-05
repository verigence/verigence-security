from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.dependencies import repository, token_service
from verigence_security.api.routes import access
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.main import app

client = TestClient(app)


class _FakeCredentialService:
    def __init__(self, settings: Settings, session: object | None = None) -> None:
        _ = settings
        assert session is not None

    def authenticate(self, *, identifier: str, password: str) -> object:
        assert identifier == "amit@example.com"
        assert password == "safe-password-123"
        return SimpleNamespace(clerk_user=SimpleNamespace(user_id="user_clerk_active"))


class _FakeHumanActorService:
    def __init__(self, session: object) -> None:
        _ = session

    def authenticate(self, identity: object) -> object:
        assert identity.provider == "CLERK"
        assert identity.provider_subject == "user_clerk_active"
        return SimpleNamespace(
            user_id="11111111-1111-1111-1111-111111111111",
            is_super_admin=False,
        )


class _InactiveHumanActorService:
    def __init__(self, session: object) -> None:
        _ = session

    def authenticate(self, identity: object) -> object:
        _ = identity
        raise security_error("USER_NOT_ACTIVE")


class _FakeTokens:
    def __init__(self) -> None:
        self.claims: object | None = None

    def issue_human_token(self, claims: object) -> str:
        self.claims = claims
        return "security-human-token"


@pytest.fixture(autouse=True)
def _dependencies(monkeypatch: pytest.MonkeyPatch):
    fake_tokens = _FakeTokens()
    app.dependency_overrides.clear()
    app.dependency_overrides[get_settings] = lambda: Settings(platform_admin_token_ttl_minutes=15)
    app.dependency_overrides[repository] = lambda: SimpleNamespace(s=object())
    app.dependency_overrides[token_service] = lambda: fake_tokens
    monkeypatch.setattr(access, "ClerkCredentialService", _FakeCredentialService)
    monkeypatch.setattr(access, "HumanActorAuthenticationService", _FakeHumanActorService)
    yield fake_tokens
    app.dependency_overrides.clear()


def test_phase1_login_openapi_adds_optional_device_without_reintroducing_tenant_geo() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/security/v1/auth/login"]["post"]
    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    component_name = request_schema["$ref"].rsplit("/", 1)[-1]
    component = schema["components"]["schemas"][component_name]

    assert set(component["properties"]) == {"identifier", "password", "device"}
    assert set(component["required"]) == {"identifier", "password"}


def test_phase1_login_remains_backward_compatible_without_device_context(
    _dependencies: _FakeTokens,
) -> None:
    response = client.post(
        "/security/v1/auth/login",
        json={
            "identifier": "amit@example.com",
            "password": "safe-password-123",
        },
    )

    assert response.status_code == 200
    assert response.json()["accessToken"] == "security-human-token"
    assert response.json()["actorType"] == "USER"
    assert response.json()["isSuperAdmin"] is False
    assert response.json()["sessionId"]
    assert response.json()["deviceId"]
    assert _dependencies.claims.user_id == "11111111-1111-1111-1111-111111111111"
    assert _dependencies.claims.session_id
    assert _dependencies.claims.device_id


def test_phase1_login_binds_supplied_device_id_into_human_token(
    _dependencies: _FakeTokens,
) -> None:
    device_id = "22222222-2222-2222-2222-222222222222"
    response = client.post(
        "/security/v1/auth/login",
        json={
            "identifier": "amit@example.com",
            "password": "safe-password-123",
            "device": {
                "deviceId": device_id,
                "deviceType": "WEB",
                "platform": "WINDOWS",
                "browserName": "Chrome",
            },
        },
    )

    assert response.status_code == 200
    assert response.json()["deviceId"] == device_id
    assert _dependencies.claims.device_id == device_id
    assert _dependencies.claims.session_id == response.json()["sessionId"]


def test_optional_device_geo_headers_do_not_change_phase1_login(
    _dependencies: _FakeTokens,
) -> None:
    response = client.post(
        "/security/v1/auth/login",
        json={
            "identifier": "amit@example.com",
            "password": "safe-password-123",
        },
        headers={
            "X-Device-ID": "client-device-context",
            "X-Geo-Context": "opaque-client-geo-context",
        },
    )

    assert response.status_code == 200
    assert response.json()["accessToken"] == "security-human-token"
    assert response.json()["isSuperAdmin"] is False
    assert _dependencies.claims.user_id == "11111111-1111-1111-1111-111111111111"


def test_non_active_security_user_cannot_receive_human_token(
    monkeypatch: pytest.MonkeyPatch,
    _dependencies: _FakeTokens,
) -> None:
    monkeypatch.setattr(access, "HumanActorAuthenticationService", _InactiveHumanActorService)

    response = client.post(
        "/security/v1/auth/login",
        json={
            "identifier": "amit@example.com",
            "password": "safe-password-123",
        },
    )

    assert response.status_code == 403
    assert response.json()["code"] == "USER_NOT_ACTIVE"
    assert _dependencies.claims is None


def test_every_login_attempt_is_recorded_with_its_outcome(
    monkeypatch: pytest.MonkeyPatch,
    _dependencies: _FakeTokens,
) -> None:
    seen: list[dict[str, object]] = []
    monkeypatch.setattr(access, "record_login_attempt", lambda settings, **kw: seen.append(kw))
    device = {"deviceId": "22222222-2222-2222-2222-222222222222", "deviceType": "MOBILE",
              "platform": "ANDROID", "appVersion": "1.4"}
    ok = client.post(
        "/security/v1/auth/login",
        json={"identifier": "amit@example.com", "password": "safe-password-123", "device": device},
    )
    assert ok.status_code == 200

    monkeypatch.setattr(access, "HumanActorAuthenticationService", _InactiveHumanActorService)
    refused = client.post(
        "/security/v1/auth/login",
        json={"identifier": "amit@example.com", "password": "safe-password-123"},
    )
    assert refused.status_code == 403

    assert [(a["outcome"], a["reason"], a["platform"], a["app_version"]) for a in seen] == [
        ("SUCCESS", None, "ANDROID", "1.4"),
        ("FAILED", "USER_NOT_ACTIVE", None, None),
    ]
    assert seen[0]["user_id"] == "11111111-1111-1111-1111-111111111111"
    assert "safe-password-123" not in repr(seen)


def test_a_failed_recording_never_blocks_the_sign_in(
    monkeypatch: pytest.MonkeyPatch,
    _dependencies: _FakeTokens,
) -> None:
    # No database is configured in this test, so recording has nowhere to write: the sign-in still works.
    response = client.post(
        "/security/v1/auth/login",
        json={"identifier": "amit@example.com", "password": "safe-password-123"},
    )
    assert response.status_code == 200
