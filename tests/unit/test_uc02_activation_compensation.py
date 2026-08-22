from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from verigence_security.api.routes.tenant_activation_compensation import (
    restore_tenant_to_configuring,
)
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

TENANT_ID = "00000000-0000-4000-8000-000000000010"
ACTOR_ID = "00000000-0000-4000-8000-000000000001"
NOW = datetime(2026, 8, 23, 1, 0, tzinfo=UTC)


class _Result:
    def __init__(self, row: dict[str, Any] | None = None) -> None:
        self._row = row

    def mappings(self) -> _Result:
        return self

    def first(self) -> dict[str, Any] | None:
        return self._row


class _FakeSession:
    def __init__(self, status: str) -> None:
        self.status = status
        self.committed = False
        self.rolled_back = False
        self.statements: list[str] = []

    def execute(self, statement: object, params: dict[str, object]) -> _Result:
        sql = str(statement)
        self.statements.append(sql)
        if "SELECT tenant_id,tenant_code,tenant_name,status" in sql:
            return _Result(
                {
                    "tenant_id": TENANT_ID,
                    "tenant_code": "tenant-test",
                    "tenant_name": "Test Project",
                    "status": self.status,
                    "created_at_utc": NOW,
                    "updated_at_utc": NOW,
                }
            )
        if "UPDATE security.tenants" in sql:
            self.status = "CONFIGURING"
            return _Result(
                {
                    "tenant_id": TENANT_ID,
                    "tenant_code": "tenant-test",
                    "tenant_name": "Test Project",
                    "status": "CONFIGURING",
                    "created_at_utc": NOW,
                    "updated_at_utc": NOW,
                }
            )
        if "INSERT INTO security.admin_change_records" in sql:
            return _Result()
        raise AssertionError(f"unexpected SQL: {sql}; params={params}")

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


def _actor() -> HumanActorContext:
    return HumanActorContext(
        user_id=ACTOR_ID,
        clerk_subject="user_super_admin",
        admin_scopes=(AdminScope("SuperAdmin", "PLATFORM", None),),
    )


def _request() -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(correlation_id="uc02-activation-compensate"))


def test_active_tenant_is_restored_to_configuring_and_audited() -> None:
    session = _FakeSession("ACTIVE")

    result = restore_tenant_to_configuring(
        TENANT_ID,
        _request(),  # type: ignore[arg-type]
        _actor(),
        session,  # type: ignore[arg-type]
    )

    assert result["status"] == "CONFIGURING"
    assert session.status == "CONFIGURING"
    assert session.committed is True
    assert session.rolled_back is False
    assert any("UPDATE security.tenants" in sql for sql in session.statements)
    assert any("platform.tenant.activation_compensate" in sql for sql in session.statements)


def test_configuring_tenant_compensation_is_idempotent_without_write() -> None:
    session = _FakeSession("CONFIGURING")

    result = restore_tenant_to_configuring(
        TENANT_ID,
        _request(),  # type: ignore[arg-type]
        _actor(),
        session,  # type: ignore[arg-type]
    )

    assert result["status"] == "CONFIGURING"
    assert session.committed is False
    assert not any("UPDATE security.tenants" in sql for sql in session.statements)
