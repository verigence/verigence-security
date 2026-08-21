from __future__ import annotations

from typing import Any

import pytest

from verigence_security.services.v2_user_directory import V2UserDirectoryService


class _Mappings:
    def __iter__(self) -> Any:
        return iter(())


class _ExecuteResult:
    def mappings(self) -> _Mappings:
        return _Mappings()


class _CapturingSession:
    def __init__(self) -> None:
        self.sql = ""
        self.params: dict[str, Any] = {}

    def execute(self, statement: object, params: dict[str, Any]) -> _ExecuteResult:
        self.sql = str(statement)
        self.params = params
        return _ExecuteResult()


@pytest.mark.parametrize(
    ("status", "search", "expected_sql", "unexpected_sql", "expected_params"),
    [
        (
            "PENDING",
            None,
            ("u.status=:status",),
            (":status IS NULL", ":search IS NULL"),
            {"status": "PENDING"},
        ),
        (None, None, (), (":status", ":search"), {}),
        (None, "Alice", (":search",), (":status", ":search IS NULL"), {"search": "alice"}),
        (
            "ACTIVE",
            "Example",
            ("u.status=:status", ":search"),
            (":status IS NULL", ":search IS NULL"),
            {"status": "ACTIVE", "search": "example"},
        ),
    ],
)
def test_list_users_only_binds_supplied_optional_filters(
    status: str | None,
    search: str | None,
    expected_sql: tuple[str, ...],
    unexpected_sql: tuple[str, ...],
    expected_params: dict[str, str],
) -> None:
    session = _CapturingSession()
    service = V2UserDirectoryService(session)  # type: ignore[arg-type]

    assert service.list_users(status=status, search=search, limit=200, offset=0) == []

    for fragment in expected_sql:
        assert fragment in session.sql
    for fragment in unexpected_sql:
        assert fragment not in session.sql
    assert session.params == {"limit": 200, "offset": 0, **expected_params}
