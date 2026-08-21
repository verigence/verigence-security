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
    def __init__(self, settings: Settings) -> None:
        _ = settings

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


def test_phase1_login_openapi_has_only_identifier_and_password_body_fields() -> None:
    schema = app.openapi()
    operation = schema["paths"]["/security/v1/auth/login"]["post"]
    request_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    component_name = request_schema["$ref"].rsplit("/", 1)[-1]
    component = schema["components"]["schemas"][component_name]

    assert set(component["properties"]) == {"identifier", "password"}
    assert set(component["required"]) == {"identifier", "password"}


def test_phase1_login_requires_no_tenant_device_geo_or_idempotency_header(
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
    assert _dependencies.claims.user_id == "11111111-1111-1111-1111-111111111111"


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
