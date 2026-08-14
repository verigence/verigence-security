from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy.orm import Session

from verigence_security.services.initial_super_admin import InitialSuperAdminProvisioningService


class _FakeMappings:
    def __init__(self, row: dict[str, object] | None) -> None:
        self.row = row

    def first(self) -> dict[str, object] | None:
        return self.row


class _FakeResult:
    def __init__(
        self,
        *,
        row: dict[str, object] | None = None,
        first_value: object | None = None,
    ) -> None:
        self.row = row
        self.first_value = first_value

    def mappings(self) -> _FakeMappings:
        return _FakeMappings(self.row)

    def first(self) -> object | None:
        return self.first_value


class _FakeSession:
    def __init__(
        self,
        *,
        existing_user_id: str | None = None,
        target_active: bool = False,
        any_active: bool = False,
    ) -> None:
        self.existing_user_id = existing_user_id
        self.target_active = target_active
        self.any_active = any_active
        self.inserts: list[str] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(self, statement: object, params: dict[str, Any] | None = None) -> _FakeResult:
        sql = str(statement)
        if "pg_advisory_xact_lock" in sql:
            return _FakeResult()
        if "FROM security.external_identities e" in sql:
            row = {"user_id": self.existing_user_id} if self.existing_user_id else None
            return _FakeResult(row=row)
        if "FROM security.platform_user_role_assignments" in sql and "user_id=:user_id" in sql:
            return _FakeResult(first_value=(1,) if self.target_active else None)
        if "FROM security.platform_user_role_assignments" in sql:
            return _FakeResult(first_value=(1,) if self.any_active else None)
        if "INSERT INTO" in sql:
            self.inserts.append(sql)
            return _FakeResult()
        raise AssertionError(f"Unexpected SQL in test: {sql}")

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _service(fake: _FakeSession) -> InitialSuperAdminProvisioningService:
    return InitialSuperAdminProvisioningService(cast(Session, fake))


def test_initial_super_admin_is_created_once() -> None:
    fake = _FakeSession()

    result = _service(fake).provision(
        clerk_user_id="user_3HtNkIWp32cD9HC7KzDbZdJkr2h",
        display_name="superadmin",
    )

    assert result.created is True
    assert len(fake.inserts) == 5
    assert any("security.external_identities" in sql for sql in fake.inserts)
    assert any("security.platform_user_role_assignments" in sql for sql in fake.inserts)
    assert fake.commits == 1
    assert fake.rollbacks == 0


def test_existing_bound_super_admin_is_idempotent() -> None:
    fake = _FakeSession(existing_user_id="00000000-0000-0000-0000-000000000001", target_active=True)

    result = _service(fake).provision(clerk_user_id="user_existing")

    assert result.created is False
    assert result.user_id == "00000000-0000-0000-0000-000000000001"
    assert fake.inserts == []
    assert fake.commits == 1
    assert fake.rollbacks == 0


def test_initial_provisioning_refuses_to_replace_another_super_admin() -> None:
    fake = _FakeSession(any_active=True)

    with pytest.raises(RuntimeError, match="different active Platform Super Admin"):
        _service(fake).provision(clerk_user_id="user_new")

    assert fake.inserts == []
    assert fake.commits == 0
    assert fake.rollbacks == 1


def test_initial_provisioning_requires_clerk_user_identifier() -> None:
    fake = _FakeSession()

    with pytest.raises(ValueError, match="immutable Clerk user_ identifier"):
        _service(fake).provision(clerk_user_id="superadmin")

    assert fake.inserts == []
