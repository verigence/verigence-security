from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from verigence_security.api.routes import human_refresh
from verigence_security.core.errors import SecurityError

SESSION_ID = "33333333-3333-3333-3333-333333333333"
DEVICE_ID = "44444444-4444-4444-4444-444444444444"


class _FakeTokens:
    def __init__(self) -> None:
        self.issued = None

    def verify_human_token(self, token: str):
        assert token == "current-token"
        return {"sub": "user-1", "session_id": SESSION_ID, "device_id": DEVICE_ID}

    def issue_human_token(self, claims):
        self.issued = claims
        return "replacement-token"


class _FakeActorService:
    def __init__(self, session) -> None:
        assert session == "db-session"

    def authenticate_user_id(self, user_id: str):
        assert user_id == "user-1"
        return SimpleNamespace(user_id="user-1", is_super_admin=True)


class _FakeObservationRepository:
    status = "ACTIVE"

    def __init__(self, session) -> None:
        assert session == "db-session"
        self.touched = False

    def session_status(self, *, user_id, session_id, device_id):
        assert user_id == "user-1"
        assert str(session_id) == SESSION_ID
        assert str(device_id) == DEVICE_ID
        return self.status

    def touch_active_session(self, **kwargs):
        assert kwargs["user_id"] == "user-1"
        self.touched = True


def test_refresh_human_access_token_rechecks_actor_session_and_reissues(monkeypatch):
    monkeypatch.setattr(human_refresh, "HumanActorAuthenticationService", _FakeActorService)
    monkeypatch.setattr(human_refresh, "HumanObservationRepository", _FakeObservationRepository)
    monkeypatch.setattr(human_refresh, "attach_trusted_user_id", lambda user_id: None)
    tokens = _FakeTokens()
    before = datetime.now(UTC)

    result = human_refresh.refresh_human_access_token(
        authorization_token="current-token",
        settings=SimpleNamespace(platform_admin_token_ttl_minutes=15),
        repo=SimpleNamespace(s="db-session"),
        tokens=tokens,
    )

    assert result["accessToken"] == "replacement-token"
    assert result["actorType"] == "USER"
    assert result["isSuperAdmin"] is True
    assert result["sessionId"] == SESSION_ID
    assert result["deviceId"] == DEVICE_ID
    assert result["expiresAtUtc"] > before
    assert tokens.issued.user_id == "user-1"
    assert tokens.issued.session_id == SESSION_ID
    assert tokens.issued.device_id == DEVICE_ID
    assert tokens.issued.expires_at == result["expiresAtUtc"]


def test_refresh_denies_explicitly_superseded_session(monkeypatch):
    class _SupersededObservationRepository(_FakeObservationRepository):
        status = "SUPERSEDED"

    monkeypatch.setattr(human_refresh, "HumanActorAuthenticationService", _FakeActorService)
    monkeypatch.setattr(
        human_refresh,
        "HumanObservationRepository",
        _SupersededObservationRepository,
    )
    monkeypatch.setattr(human_refresh, "attach_trusted_user_id", lambda user_id: None)

    with pytest.raises(SecurityError) as exc:
        human_refresh.refresh_human_access_token(
            authorization_token="current-token",
            settings=SimpleNamespace(platform_admin_token_ttl_minutes=15),
            repo=SimpleNamespace(s="db-session"),
            tokens=_FakeTokens(),
        )

    assert exc.value.code == "SESSION_SUPERSEDED"
