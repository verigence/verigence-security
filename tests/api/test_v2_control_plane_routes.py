from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import (
    platform_modules,
    v2_admin_roles,
    v2_groups,
    v2_user_lifecycle,
)
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)
TENANT = "00000000-0000-4000-8000-000000000010"
USER = "00000000-0000-4000-8000-000000000020"
ACTOR = "00000000-0000-4000-8000-000000000001"


class _FakeSession:
    pass


@pytest.fixture(autouse=True)
def _clear_dependency_overrides() -> None:
    app.dependency_overrides.clear()
    app.dependency_overrides[platform_session] = lambda: _FakeSession()
    yield
    app.dependency_overrides.clear()


def _actor(*scopes: AdminScope) -> HumanActorContext:
    return HumanActorContext(
        user_id=ACTOR,
        clerk_subject="user_test",
        admin_scopes=tuple(scopes),
    )


def _use_actor(actor: HumanActorContext) -> None:
    app.dependency_overrides[security_human_actor] = lambda: actor


def test_uc02_human_admin_context_returns_live_security_scopes() -> None:
    _use_actor(
        _actor(
            AdminScope("SuperAdmin", "PLATFORM", None),
            AdminScope("ModuleAdmin", "MODULE", "di"),
        )
    )
    response = client.get("/security/v1/platform/admin-context")
    assert response.status_code == 200
    body = response.json()
    assert body["userId"] == ACTOR
    assert body["isSuperAdmin"] is True
    assert body["adminScopes"] == [
        {"roleKey": "SuperAdmin", "scopeType": "PLATFORM", "scopeId": None},
        {"roleKey": "ModuleAdmin", "scopeType": "MODULE", "scopeId": "di"},
    ]


def test_role_aligned_groups_are_read_only_and_legacy_mutation_routes_are_inactive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_actor(_actor(AdminScope("TenantAdmin", "TENANT", TENANT)))

    class _Groups:
        def __init__(self, session: object) -> None:
            _ = session

        @staticmethod
        def tenant_exists(tenant_id: str) -> bool:
            return tenant_id == TENANT

        @staticmethod
        def list_groups(tenant_id: str) -> list[dict[str, object]]:
            assert tenant_id == TENANT
            return [
                {
                    "role_key": "PC",
                    "display_name": "Process Consultant",
                    "member_count": 2,
                }
            ]

    monkeypatch.setattr(v2_groups, "RoleAlignedGroupService", _Groups)
    response = client.get(f"/security/v1/tenants/{TENANT}/groups")
    assert response.status_code == 200
    assert response.json()[0]["roleKey"] == "PC"
    assert response.json()[0]["memberCount"] == 2

    # Old arbitrary Group and Tenant-role mutation routers are deliberately no longer
    # registered in the active FastAPI application.
    assert client.post(
        f"/security/v1/admin/tenants/{TENANT}/groups",
        json={"groupKey": "custom", "groupName": "Custom"},
    ).status_code == 404
    assert client.post(
        f"/security/v1/admin/tenants/{TENANT}/roles",
        json={"roleKey": "custom", "roleName": "Custom"},
    ).status_code == 404


def test_tenant_admin_cannot_assign_an_admin_role(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_actor(_actor(AdminScope("TenantAdmin", "TENANT", TENANT)))

    class _AdminRoles:
        def __init__(self, session: object) -> None:
            _ = session

        def assign(self, **kwargs: object) -> object:
            raise AssertionError(f"service must not be called: {kwargs}")

    monkeypatch.setattr(v2_admin_roles, "AuditedAdminRoleAssignmentService", _AdminRoles)
    response = client.put(
        f"/security/v1/tenants/{TENANT}/users/{USER}/admin-role/TenantAdmin",
        headers={"X-Correlation-ID": "admin-role-denied"},
    )
    assert response.status_code == 403
    assert response.json()["code"] == "PERMISSION_DENIED"


def test_super_admin_assigns_tenant_admin_with_correlation_audit_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_actor(_actor(AdminScope("SuperAdmin", "PLATFORM", None)))
    observed: dict[str, object] = {}

    class _AdminRoles:
        def __init__(self, session: object) -> None:
            _ = session

        def assign(self, **kwargs: object) -> object:
            observed.update(kwargs)
            return SimpleNamespace(
                changed=True,
                assignment_id="00000000-0000-4000-8000-000000000030",
                role_key="TenantAdmin",
            )

    monkeypatch.setattr(v2_admin_roles, "AuditedAdminRoleAssignmentService", _AdminRoles)
    response = client.put(
        f"/security/v1/tenants/{TENANT}/users/{USER}/admin-role/TenantAdmin",
        headers={"X-Correlation-ID": "admin-role-change"},
    )
    assert response.status_code == 200
    assert response.json()["roleKey"] == "TenantAdmin"
    assert observed["actor_user_id"] == ACTOR
    assert observed["correlation_id"] == "admin-role-change"


def test_module_permission_discovery_requires_human_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_actor(_actor())

    class _Catalog:
        def __init__(self, repository: object) -> None:
            _ = repository

        def get_catalog(self, module_key: str) -> dict[str, object]:
            raise AssertionError(f"must not read catalogue for non-admin: {module_key}")

    monkeypatch.setattr(platform_modules, "ModuleCatalogService", _Catalog)
    denied = client.get("/security/v1/platform/modules/di/permissions")
    assert denied.status_code == 403

    _use_actor(_actor(AdminScope("ModuleAdmin", "MODULE", "di")))

    class _AdminCatalog:
        def __init__(self, repository: object) -> None:
            _ = repository

        def get_catalog(self, module_key: str) -> dict[str, object]:
            assert module_key == "di"
            return {
                "permissions": [
                    {
                        "key": "di.document.read",
                        "name": "Read Document",
                        "description": None,
                        "status": "ACTIVE",
                        "catalogVersion": "2.2",
                    }
                ]
            }

    monkeypatch.setattr(platform_modules, "ModuleCatalogService", _AdminCatalog)
    allowed = client.get("/security/v1/platform/modules/di/permissions")
    assert allowed.status_code == 200
    assert allowed.json()[0]["key"] == "di.document.read"


def test_lifecycle_route_uses_security_human_actor_and_v2_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_actor(_actor(AdminScope("SuperAdmin", "PLATFORM", None)))
    observed: dict[str, object] = {}

    class _Lifecycle:
        def __init__(self, session: object) -> None:
            _ = session

        def transition(self, **kwargs: object) -> object:
            observed.update(kwargs)
            return SimpleNamespace(
                user_id=USER,
                status="REJECTED",
                previous_status="PENDING",
                changed=True,
                deletion_request_id=None,
            )

    monkeypatch.setattr(v2_user_lifecycle, "V2UserLifecycleService", _Lifecycle)
    monkeypatch.setattr(v2_user_lifecycle, "_clerk", lambda settings: object())
    response = client.patch(
        f"/security/v1/users/{USER}/status",
        json={"status": "REJECTED", "reason": "not approved"},
        headers={"X-Correlation-ID": "reject-user"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "REJECTED"
    assert observed["actor"].is_super_admin is True  # type: ignore[union-attr]
    assert observed["correlation_id"] == "reject-user"


def test_hard_delete_response_exposes_exact_21_day_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_actor(_actor(AdminScope("SuperAdmin", "PLATFORM", None)))
    deleted_at = datetime(2026, 8, 19, 10, 0, tzinfo=UTC)

    class _Lifecycle:
        def __init__(self, session: object) -> None:
            _ = session

        def hard_delete(self, **kwargs: object) -> object:
            _ = kwargs
            return SimpleNamespace(
                user_id=USER,
                deletion_request_id="00000000-0000-4000-8000-000000000040",
                tombstone_id="00000000-0000-4000-8000-000000000050",
                deleted_at_utc=deleted_at,
                retain_until_utc=deleted_at + timedelta(days=21),
            )

    monkeypatch.setattr(v2_user_lifecycle, "V2UserLifecycleService", _Lifecycle)
    monkeypatch.setattr(v2_user_lifecycle, "_clerk", lambda settings: object())
    response = client.delete(
        f"/security/v1/platform/users/{USER}",
        headers={"X-Correlation-ID": "delete-user"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tombstoneId"] == "00000000-0000-4000-8000-000000000050"
    assert datetime.fromisoformat(body["retainUntilUtc"]) - datetime.fromisoformat(
        body["deletedAtUtc"]
    ) == timedelta(days=21)
