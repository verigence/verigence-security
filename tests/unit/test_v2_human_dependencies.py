from __future__ import annotations

import pytest

import verigence_security.api.v2_human_dependencies as dependencies
import verigence_security.services.v2_human_actor as actor_types

USER_ID = "00000000-0000-4000-8000-000000000001"

# Regression guard for the DEV Project Administration path: the actor lookup must
# release its DB session before the downstream platform-admin route opens another.


def test_security_human_actor_releases_database_session_before_yield(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeSession:
        def close(self) -> None:
            events.append("close")

    session = FakeSession()
    actor = actor_types.HumanActorContext(
        user_id=USER_ID,
        clerk_subject="user_super_admin",
        admin_scopes=(actor_types.AdminScope("SuperAdmin", "PLATFORM", None),),
    )

    class FakeAuthenticationService:
        def __init__(self, observed_session: object) -> None:
            assert observed_session is session

        def authenticate_user_id(self, user_id: str) -> actor_types.HumanActorContext:
            assert user_id == USER_ID
            events.append("authenticate")
            return actor

    def fake_factory() -> FakeSession:
        events.append("open")
        return session

    monkeypatch.setattr(
        dependencies,
        "build_session_factory",
        lambda _settings: fake_factory,
    )
    monkeypatch.setattr(
        dependencies,
        "HumanActorAuthenticationService",
        FakeAuthenticationService,
    )

    generator = dependencies.security_human_actor(
        user_id=USER_ID,
        settings=object(),  # type: ignore[arg-type]
    )
    resolved = next(generator)

    assert resolved is actor
    assert events == ["open", "authenticate", "close"]

    with pytest.raises(StopIteration):
        next(generator)


def test_security_human_actor_releases_database_session_when_resolution_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeSession:
        def close(self) -> None:
            events.append("close")

    session = FakeSession()

    class FailingAuthenticationService:
        def __init__(self, observed_session: object) -> None:
            assert observed_session is session

        def authenticate_user_id(self, user_id: str) -> actor_types.HumanActorContext:
            assert user_id == USER_ID
            events.append("authenticate")
            raise RuntimeError("resolution failed")

    monkeypatch.setattr(
        dependencies,
        "build_session_factory",
        lambda _settings: (lambda: session),
    )
    monkeypatch.setattr(
        dependencies,
        "HumanActorAuthenticationService",
        FailingAuthenticationService,
    )

    generator = dependencies.security_human_actor(
        user_id=USER_ID,
        settings=object(),  # type: ignore[arg-type]
    )
    with pytest.raises(RuntimeError, match="resolution failed"):
        next(generator)

    assert events == ["authenticate", "close"]
