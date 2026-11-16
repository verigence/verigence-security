"""A USER's name can be changed (product owner 2026-11-16)."""
from __future__ import annotations

from typing import Any

import pytest

from verigence_security.adapters.clerk_backend import ClerkBackendError
from verigence_security.services.global_user_onboarding import GlobalUserOnboardingService

USER = "d09199ba-eb20-4107-adfe-982414ae0dc0"


class _Rows:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows

    def mappings(self) -> _Rows:
        return self

    def first(self) -> dict[str, Any] | None:
        return self.rows[0] if self.rows else None

    def __iter__(self):
        return iter(self.rows)


class _Session:
    def __init__(self) -> None:
        self.user = {"user_id": USER, "display_name": "Vicks Rockstar", "first_name": "Vicks",
                     "last_name": "Rockstar", "clerk_user_id": "user_clerk", "primary_email": "a@example.test",
                     "primary_mobile": None, "status": "ACTIVE", "created_at_utc": None, "updated_at_utc": None,
                     "onboarding_request_id": None, "onboarding_status": None}
        self.audits: list[dict[str, Any]] = []
        self.committed = False

    def execute(self, statement: Any, params: dict[str, Any] | None = None) -> _Rows:
        sql = str(statement)
        params = params or {}
        if sql.strip().startswith("UPDATE security.users"):
            self.user.update(display_name=params["display"], first_name=params["first"], last_name=params["last"])
        elif "admin_change_records" in sql:
            self.audits.append(params)
        return _Rows([dict(self.user)])

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        pass


class _Clerk:
    def __init__(self, fail: bool = False) -> None:
        self.fail, self.calls = fail, []

    def update_user_profile(self, clerk_user_id: str, *, first_name: str, last_name: str) -> None:
        self.calls.append((clerk_user_id, first_name, last_name))
        if self.fail:
            raise ClerkBackendError("down")


def _rename(session: _Session, clerk: _Clerk | None, first: str = " Akansh ", last: str = "Chopra") -> dict[str, Any]:
    return GlobalUserOnboardingService(session, settings=None).rename_user(  # type: ignore[arg-type]
        user_id=USER, first_name=first, last_name=last, actor_user_id="admin", reason="Wrong name",
        correlation_id="c1", clerk=clerk)  # type: ignore[arg-type]


def test_rename_changes_the_name_everywhere_and_is_audited() -> None:
    session, clerk = _Session(), _Clerk()
    result = _rename(session, clerk)
    assert result["display_name"] == "Akansh Chopra" and result["clerkSynced"] is True
    assert session.committed and session.audits
    assert clerk.calls == [("user_clerk", "Akansh", "Chopra")]


def test_a_clerk_failure_keeps_the_new_name() -> None:
    session = _Session()
    result = _rename(session, _Clerk(fail=True))
    assert result["display_name"] == "Akansh Chopra" and result["clerkSynced"] is False


def test_a_first_name_is_required() -> None:
    with pytest.raises(ValueError):
        _rename(_Session(), None, first="  ")
