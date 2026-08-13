from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from verigence_security.core.errors import SecurityError
from verigence_security.services.session_lifecycle import UserSessionLifecycleService


@dataclass
class FakeLifecycleRepository:
    session: dict[str, Any] | None
    revoke_result: bool = True
    commits: int = 0
    rollbacks: int = 0
    revoked_ids: list[str] = field(default_factory=list)

    def user_session_for_update(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> dict[str, Any] | None:
        _ = (access_session_id, tenant_id, user_id)
        return self.session

    def revoke_active_user_session(
        self,
        *,
        access_session_id: str,
        tenant_id: str,
        user_id: str,
    ) -> bool:
        _ = (tenant_id, user_id)
        self.revoked_ids.append(access_session_id)
        return self.revoke_result

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def test_refresh_requires_new_geo_sample() -> None:
    with pytest.raises(SecurityError) as exc_info:
        UserSessionLifecycleService.require_refresh_geo(None)
    assert exc_info.value.code == "GEO_REQUIRED"


def test_revoke_commits_only_active_session_transition() -> None:
    repository = FakeLifecycleRepository(session={"status": "ACTIVE"})
    service = UserSessionLifecycleService(repository)  # type: ignore[arg-type]

    assert service.revoke(
        access_session_id="session-1",
        tenant_id="tenant-1",
        user_id="user-1",
    )
    assert repository.revoked_ids == ["session-1"]
    assert repository.commits == 1
    assert repository.rollbacks == 0


def test_revoke_does_not_mutate_non_active_session() -> None:
    repository = FakeLifecycleRepository(session={"status": "REVOKED"})
    service = UserSessionLifecycleService(repository)  # type: ignore[arg-type]

    assert not service.revoke(
        access_session_id="session-1",
        tenant_id="tenant-1",
        user_id="user-1",
    )
    assert repository.revoked_ids == []
    assert repository.commits == 0
    assert repository.rollbacks == 1
