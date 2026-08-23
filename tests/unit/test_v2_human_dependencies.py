from __future__ import annotations

import pytest

from verigence_security.api import v2_human_dependencies as dependencies
from verigence_security.services.v2_human_actor import (
    AdminScope,
    HumanActorContext,
)


USER_ID = "00000000-0000-4000-8000-000000000001"


def test_security_human_actor_releases_database_session_before_yield(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class FakeSession:
        def close(self) -> None:
            events.append("close")

    session = FakeSession()
    actor = HumanActorContext(
        user_id=USER_ID,
        clerk_subject="user_super_admin",
        admin_scopes=(AdminScope("SuperAdmin", "PLATFORM", None),),
    )

    class FakeAuthenticationService:
        def __init__(self, observed_session: object) -> None:
            assert observed_session is session

        def authenticate_user_id(self, user_id: str) -> HumanActorContext:
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
