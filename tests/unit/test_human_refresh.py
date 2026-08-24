from datetime import UTC, datetime
from types import SimpleNamespace

from verigence_security.api.routes import human_refresh


class _FakeTokens:
    def __init__(self) -> None:
        self.issued = None

    def verify_human_token(self, token: str):
        assert token == "current-token"
        return {"sub": "user-1"}

    def issue_human_token(self, claims):
        self.issued = claims
        return "replacement-token"


class _FakeActorService:
    def __init__(self, session) -> None:
        assert session == "db-session"

    def authenticate_user_id(self, user_id: str):
        assert user_id == "user-1"
        return SimpleNamespace(user_id="user-1", is_super_admin=True)


def test_refresh_human_access_token_rechecks_actor_and_reissues(monkeypatch):
    monkeypatch.setattr(human_refresh, "HumanActorAuthenticationService", _FakeActorService)
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
    assert result["expiresAtUtc"] > before
    assert tokens.issued.user_id == "user-1"
    assert tokens.issued.expires_at == result["expiresAtUtc"]
