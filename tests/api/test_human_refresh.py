from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.dependencies import repository, token_service
from verigence_security.api.routes import access
from verigence_security.config import Settings, get_settings
from verigence_security.main import app

client = TestClient(app)

SESSION_ID = "33333333-3333-3333-3333-333333333333"
DEVICE_ID = "44444444-4444-4444-4444-444444444444"


class _FakeHumanActorService:
    def __init__(self, session: object) -> None:
        _ = session

    def authenticate_user_id(self, user_id: str) -> object:
        assert user_id == "user-1"
        return SimpleNamespace(user_id="user-1", is_super_admin=True)


class _FakeObservationRepository:
    status = "ACTIVE"

    def __init__(self, session: object) -> None:
        _ = session
        self.touched = False

    def session_status(self, *, user_id: str, session_id: object, device_id: object) -> str:
        assert user_id == "user-1"
        assert str(session_id) == SESSION_ID
        assert str(device_id) == DEVICE_ID
        return self.status

    def touch_active_session(self, **kwargs: object) -> None:
        assert kwargs["user_id"] == "user-1"
        self.touched = True


class _FakeTokens:
    def __init__(self) -> None:
        self.issued: object | None = None

    def verify_human_token(self, token: str) -> dict[str, object]:
        assert token == "current-token"
        return {"sub": "user-1", "session_id": SESSION_ID, "device_id": DEVICE_ID}

    def issue_human_token(self, claims: object) -> str:
        self.issued = claims
        return "replacement-token"


@pytest.fixture(autouse=True)
def _dependencies(monkeypatch: pytest.MonkeyPatch):
    fake_tokens = _FakeTokens()
    app.dependency_overrides.clear()
    app.dependency_overrides[get_settings] = lambda: Settings(platform_admin_token_ttl_minutes=15)
    app.dependency_overrides[repository] = lambda: SimpleNamespace(s=object())
    app.dependency_overrides[token_service] = lambda: fake_tokens
    monkeypatch.setattr(access, "HumanActorAuthenticationService", _FakeHumanActorService)
    monkeypatch.setattr(access, "HumanObservationRepository", _FakeObservationRepository)
    yield fake_tokens
    app.dependency_overrides.clear()


def test_refresh_rechecks_actor_and_session_then_reissues(_dependencies: _FakeTokens) -> None:
    response = client.post(
        "/security/v1/auth/refresh",
        headers={"Authorization": "Bearer current-token"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["accessToken"] == "replacement-token"
    assert body["actorType"] == "USER"
    assert body["isSuperAdmin"] is True
    assert body["sessionId"] == SESSION_ID
    assert body["deviceId"] == DEVICE_ID
    assert _dependencies.issued.user_id == "user-1"
    assert _dependencies.issued.session_id == SESSION_ID
    assert _dependencies.issued.device_id == DEVICE_ID


def test_refresh_denies_explicitly_superseded_session(
    monkeypatch: pytest.MonkeyPatch,
    _dependencies: _FakeTokens,
) -> None:
    class _SupersededObservationRepository(_FakeObservationRepository):
        status = "SUPERSEDED"

    monkeypatch.setattr(access, "HumanObservationRepository", _SupersededObservationRepository)

    response = client.post(
        "/security/v1/auth/refresh",
        headers={"Authorization": "Bearer current-token"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "SESSION_SUPERSEDED"
    assert _dependencies.issued is None


def test_refresh_denies_revoked_session(
    monkeypatch: pytest.MonkeyPatch,
    _dependencies: _FakeTokens,
) -> None:
    class _RevokedObservationRepository(_FakeObservationRepository):
        status = "REVOKED"

    monkeypatch.setattr(access, "HumanObservationRepository", _RevokedObservationRepository)

    response = client.post(
        "/security/v1/auth/refresh",
        headers={"Authorization": "Bearer current-token"},
    )

    assert response.status_code == 401
    assert response.json()["code"] == "SESSION_REVOKED"


def test_refresh_requires_bearer_token(_dependencies: _FakeTokens) -> None:
    response = client.post("/security/v1/auth/refresh")

    assert response.status_code == 401
