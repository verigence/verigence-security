from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from verigence_security.services import platform_admin as platform_admin_module
from verigence_security.services.platform_admin import (
    PlatformTenantService,
    TenantCreateIdempotencyConflict,
)

ACTOR = "00000000-0000-4000-8000-000000000001"


@dataclass
class _FakeRepository:
    tenants: dict[str, dict[str, object]] = field(default_factory=dict)
    receipts: dict[tuple[str, str], dict[str, object]] = field(default_factory=dict)
    create_count: int = 0
    lock_count: int = 0
    commits: int = 0
    rollbacks: int = 0

    def acquire_tenant_create_idempotency_lock(
        self,
        *,
        actor_user_id: str,
        idempotency_key: str,
    ) -> None:
        _ = actor_user_id, idempotency_key
        self.lock_count += 1

    def tenant_create_receipt(
        self,
        *,
        actor_user_id: str,
        idempotency_key: str,
    ) -> dict[str, object] | None:
        return self.receipts.get((actor_user_id, idempotency_key))

    def create_tenant(
        self,
        *,
        tenant_id: str,
        tenant_code: str,
        tenant_name: str,
        now: object,
    ) -> None:
        self.create_count += 1
        self.tenants[tenant_id] = {
            "tenant_id": tenant_id,
            "tenant_code": tenant_code,
            "tenant_name": tenant_name,
            "status": "CONFIGURING",
            "created_at_utc": now,
            "updated_at_utc": now,
        }

    def insert_admin_change(self, **values: Any) -> None:
        if values["operation_key"] != "platform.tenant.create":
            return
        after_state = json.loads(str(values["after_state_json"]))
        idempotency_key = after_state.get("idempotencyKey")
        if idempotency_key is None:
            return
        self.receipts[(str(values["actor_user_id"]), str(idempotency_key))] = {
            "resource_id": str(values["resource_id"]),
            "tenant_name": str(after_state["tenantName"]),
        }

    def tenant_by_id(self, tenant_id: str) -> dict[str, object] | None:
        return self.tenants.get(tenant_id)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


class _TenantService(PlatformTenantService):
    def _seed_v2_tenant_role_defaults(self, **values: object) -> None:
        _ = values

    def _seed_standard_tenant_roles(self, **values: object) -> None:
        _ = values


def test_tenant_create_replays_same_result_for_same_idempotency_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _FakeRepository()
    monkeypatch.setattr(
        platform_admin_module,
        "PlatformAdminRepository",
        lambda _session: repository,
    )
    service = _TenantService(object())  # type: ignore[arg-type]

    first = service.create_tenant(
        actor_user_id=ACTOR,
        tenant_code="tenant-first",
        tenant_name="Hyundai West Audit Project",
        correlation_id="corr-first",
        idempotency_key="project-create-001",
    )
    second = service.create_tenant(
        actor_user_id=ACTOR,
        tenant_code="tenant-second",
        tenant_name="Hyundai West Audit Project",
        correlation_id="corr-retry",
        idempotency_key="project-create-001",
    )

    assert first["tenant_id"] == second["tenant_id"]
    assert second["tenant_code"] == "tenant-first"
    assert repository.create_count == 1
    assert repository.lock_count == 2
    assert repository.rollbacks == 0


def test_tenant_create_rejects_same_key_with_different_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = _FakeRepository()
    monkeypatch.setattr(
        platform_admin_module,
        "PlatformAdminRepository",
        lambda _session: repository,
    )
    service = _TenantService(object())  # type: ignore[arg-type]

    service.create_tenant(
        actor_user_id=ACTOR,
        tenant_code="tenant-first",
        tenant_name="Hyundai West Audit Project",
        correlation_id="corr-first",
        idempotency_key="project-create-002",
    )

    with pytest.raises(TenantCreateIdempotencyConflict):
        service.create_tenant(
            actor_user_id=ACTOR,
            tenant_code="tenant-second",
            tenant_name="Different Project",
            correlation_id="corr-conflict",
            idempotency_key="project-create-002",
        )

    assert repository.create_count == 1
    assert repository.rollbacks == 1
