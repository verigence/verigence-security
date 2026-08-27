from __future__ import annotations

from typing import Any

from verigence_security.services.v2_human_actor import HumanActorContext
from verigence_security.services.v2_user_lifecycle import V2UserLifecycleService


class _FakeSession:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(self, statement: Any, parameters: dict[str, object] | None = None) -> None:
        self.statements.append(str(statement))

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class _FakeClerk:
    def __init__(self) -> None:
        self.banned: list[str] = []

    def ban_user(self, clerk_user_id: str) -> None:
        self.banned.append(clerk_user_id)


def test_rejected_user_can_enter_delete_request_flow() -> None:
    session = _FakeSession()
    service = V2UserLifecycleService(session)  # type: ignore[arg-type]
    actor = HumanActorContext(user_id="admin-user", clerk_subject="admin-clerk", admin_scopes=())
    clerk = _FakeClerk()

    service._user_for_update = lambda user_id: {  # type: ignore[method-assign]
        "user_id": user_id,
        "status": "REJECTED",
        "display_name": "Rejected User",
        "primary_email": "rejected@example.test",
    }
    service._clerk_subject = lambda user_id: "clerk-rejected"  # type: ignore[method-assign]
    service._is_active_super_admin = lambda user_id: False  # type: ignore[method-assign]
    service._require_deletion_maker = lambda actor, user_id: None  # type: ignore[method-assign]
    service._audit = lambda **kwargs: None  # type: ignore[method-assign]

    result = service.transition(
        user_id="rejected-user",
        requested_status="DISABLED",
        actor=actor,
        reason_code="DELETE_REQUEST",
        reason="Rejected registration cleanup",
        correlation_id="uc001-rejected-delete-test",
        clerk=clerk,  # type: ignore[arg-type]
    )

    assert result.previous_status == "REJECTED"
    assert result.status == "DISABLED"
    assert result.changed is True
    assert result.deletion_request_id is not None
    assert session.commits == 1
    assert session.rollbacks == 0
    assert clerk.banned == ["clerk-rejected"]
    assert any("INSERT INTO security.user_deletion_requests" in statement for statement in session.statements)
