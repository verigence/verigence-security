from __future__ import annotations

from typing import Any, cast

import pytest
from sqlalchemy.orm import Session

from verigence_security.services.initial_super_admin import (
    PHASE1_SUPER_ADMIN_CLERK_USER_ID,
    InitialSuperAdminProvisioningService,
)


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
        identity_status: str = "ACTIVE",
        user_status: str = "ACTIVE",
        principal_status: str = "ACTIVE",
        legacy_super_admin_user_id: str | None = None,
        v2_super_admin_user_id: str | None = None,
        target_legacy_active: bool = False,
        target_v2_active: bool = False,
        has_operating_role: bool = False,
    ) -> None:
        self.existing_user_id = existing_user_id
        self.identity_status = identity_status
        self.user_status = user_status
        self.principal_status = principal_status
        self.legacy_super_admin_user_id = legacy_super_admin_user_id
        self.v2_super_admin_user_id = v2_super_admin_user_id
        self.target_legacy_active = target_legacy_active
        self.target_v2_active = target_v2_active
        self.has_operating_role = has_operating_role
        self.inserts: list[str] = []
        self.commits = 0
        self.rollbacks = 0

    def execute(self, statement: object, params: dict[str, Any] | None = None) -> _FakeResult:
        sql = str(statement)
        params = params or {}
        if "pg_advisory_xact_lock" in sql:
            return _FakeResult()
        if "FROM security.external_identities e" in sql:
            row = None
            if self.existing_user_id:
                row = {
                    "user_id": self.existing_user_id,
                    "identity_status": self.identity_status,
                    "user_status": self.user_status,
                    "principal_status": self.principal_status,
                }
            return _FakeResult(row=row)
        if (
            "FROM security.platform_user_role_assignments" in sql
            and "approved_user_id" in sql
        ):
            approved = params.get("approved_user_id")
            conflict = (
                self.legacy_super_admin_user_id is not None
                and self.legacy_super_admin_user_id != approved
            )
            return _FakeResult(first_value=(1,) if conflict else None)
        if (
            "FROM security.user_admin_role_assignments" in sql
            and "approved_user_id" in sql
        ):
            approved = params.get("approved_user_id")
            conflict = (
                self.v2_super_admin_user_id is not None
                and self.v2_super_admin_user_id != approved
            )
            return _FakeResult(first_value=(1,) if conflict else None)
        if "FROM security.user_tenant_operating_roles" in sql:
            return _FakeResult(first_value=(1,) if self.has_operating_role else None)
        if (
            "FROM security.platform_user_role_assignments" in sql
            and "user_id=:user_id" in sql
        ):
            return _FakeResult(first_value=(1,) if self.target_legacy_active else None)
        if (
            "FROM security.user_admin_role_assignments" in sql
            and "user_id=:user_id" in sql
        ):
            return _FakeResult(first_value=(1,) if self.target_v2_active else None)
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


def test_initial_super_admin_is_created_in_legacy_and_v2_models() -> None:
    fake = _FakeSession()

    result = _service(fake).provision(
        clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID,
        display_name="superadmin",
    )

    assert result.created is True
    assert len(fake.inserts) == 6
    assert any("security.external_identities" in sql for sql in fake.inserts)
    assert any("security.platform_user_role_assignments" in sql for sql in fake.inserts)
    assert any("security.user_admin_role_assignments" in sql for sql in fake.inserts)
    assert fake.commits == 1
    assert fake.rollbacks == 0


def test_existing_bound_super_admin_with_both_assignments_is_idempotent() -> None:
    user_id = "00000000-0000-0000-0000-000000000001"
    fake = _FakeSession(
        existing_user_id=user_id,
        legacy_super_admin_user_id=user_id,
        v2_super_admin_user_id=user_id,
        target_legacy_active=True,
        target_v2_active=True,
    )

    result = _service(fake).provision(clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID)

    assert result.created is False
    assert result.user_id == user_id
    assert fake.inserts == []
    assert fake.commits == 1
    assert fake.rollbacks == 0


def test_existing_legacy_super_admin_is_reconciled_into_v2_assignment() -> None:
    user_id = "00000000-0000-0000-0000-000000000001"
    fake = _FakeSession(
        existing_user_id=user_id,
        legacy_super_admin_user_id=user_id,
        target_legacy_active=True,
        target_v2_active=False,
    )

    result = _service(fake).provision(clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID)

    assert result.created is False
    assert any("security.user_admin_role_assignments" in sql for sql in fake.inserts)
    assert any("security.admin_change_records" in sql for sql in fake.inserts)
    assert not any("security.platform_user_role_assignments" in sql for sql in fake.inserts)
    assert fake.commits == 1


def test_existing_exact_identity_can_receive_missing_legacy_and_v2_assignments() -> None:
    fake = _FakeSession(existing_user_id="00000000-0000-0000-0000-000000000001")

    result = _service(fake).provision(clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID)

    assert result.created is False
    assert any("security.platform_user_role_assignments" in sql for sql in fake.inserts)
    assert any("security.user_admin_role_assignments" in sql for sql in fake.inserts)
    assert any("security.admin_change_records" in sql for sql in fake.inserts)


def test_initial_provisioning_refuses_different_legacy_super_admin() -> None:
    fake = _FakeSession(
        legacy_super_admin_user_id="00000000-0000-0000-0000-000000000099"
    )

    with pytest.raises(RuntimeError, match="different active Platform Super Admin"):
        _service(fake).provision(clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID)

    assert fake.inserts == []
    assert fake.commits == 0
    assert fake.rollbacks == 1


def test_initial_provisioning_refuses_different_v2_super_admin() -> None:
    fake = _FakeSession(v2_super_admin_user_id="00000000-0000-0000-0000-000000000099")

    with pytest.raises(RuntimeError, match="different active v2 SuperAdmin"):
        _service(fake).provision(clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID)

    assert fake.inserts == []
    assert fake.rollbacks == 1


def test_super_admin_cannot_have_active_operating_role() -> None:
    user_id = "00000000-0000-0000-0000-000000000001"
    fake = _FakeSession(existing_user_id=user_id, has_operating_role=True)

    with pytest.raises(RuntimeError, match="cannot have an ACTIVE operating role"):
        _service(fake).provision(clerk_user_id=PHASE1_SUPER_ADMIN_CLERK_USER_ID)

    assert fake.inserts == []
    assert fake.rollbacks == 1


def test_initial_provisioning_requires_exact_approved_clerk_user_identifier() -> None:
    fake = _FakeSession()

    with pytest.raises(ValueError, match="approved Phase-1 identity"):
        _service(fake).provision(clerk_user_id="user_someone_else")

    assert fake.inserts == []
