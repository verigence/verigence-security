from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import v2_rbac
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)


class _ExistsResult:
    def first(self) -> tuple[int] | None:
        return (1,)


class _FakeSession:
    def execute(self, statement: object, params: dict[str, Any] | None = None) -> _ExistsResult:
        _ = statement, params
        return _ExistsResult()


@pytest.fixture(autouse=True)
def _clear_dependency_overrides() -> None:
    app.dependency_overrides.clear()
    app.dependency_overrides[platform_session] = lambda: _FakeSession()
    yield
    app.dependency_overrides.clear()


def _actor(*scopes: AdminScope) -> HumanActorContext:
    return HumanActorContext(
        user_id="00000000-0000-0000-0000-000000000001",
        clerk_subject="user_test",
        admin_scopes=tuple(scopes),
    )


def _use_actor(actor: HumanActorContext) -> None:
    app.dependency_overrides[security_human_actor] = lambda: actor


def test_role_catalogue_accepts_active_security_human(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_actor(_actor())

    class _Roles:
        def __init__(self, session: object) -> None:
            _ = session

        def list_roles(self) -> list[dict[str, object]]:
            return [
                {
                    "role_key": "PC",
                    "role_class": "OPERATING",
                    "display_name": "Process Consultant",
                    "status": "ACTIVE",
                }
            ]

    monkeypatch.setattr(v2_rbac, "RoleDefinitionService", _Roles)
    response = client.get("/security/v1/roles")

    assert response.status_code == 200
    assert response.json() == [
        {
            "roleKey": "PC",
            "roleClass": "OPERATING",
            "displayName": "Process Consultant",
            "status": "ACTIVE",
        }
    ]


def test_tenant_admin_can_set_operating_role_in_own_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = "00000000-0000-0000-0000-000000000010"
    actor = _actor(AdminScope("TenantAdmin", "TENANT", tenant_id))
    _use_actor(actor)
    observed: dict[str, object] = {}

    class _OperatingRoles:
        def __init__(self, session: object) -> None:
            _ = session

        def set_role(self, **kwargs: object) -> object:
            observed.update(kwargs)
            return SimpleNamespace(
                changed=True,
                assignment_id="00000000-0000-0000-0000-000000000020",
                role_key="TL",
            )

    monkeypatch.setattr(v2_rbac, "OperatingRoleAssignmentService", _OperatingRoles)
    response = client.put(
        f"/security/v1/tenants/{tenant_id}/users/00000000-0000-0000-0000-000000000030/operating-role",
        json={"roleKey": "TL"},
        headers={"X-Correlation-ID": "v2-role-test"},
    )

    assert response.status_code == 200
    assert response.json()["roleKey"] == "TL"
    assert observed["tenant_id"] == tenant_id
    assert observed["actor_user_id"] == actor.user_id
    assert observed["correlation_id"] == "v2-role-test"


def test_tenant_admin_cannot_assign_role_in_another_tenant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_actor(
        _actor(
            AdminScope(
                "TenantAdmin",
                "TENANT",
                "00000000-0000-0000-0000-000000000010",
            )
        )
    )

    class _OperatingRoles:
        def __init__(self, session: object) -> None:
            _ = session

        def set_role(self, **kwargs: object) -> object:
            raise AssertionError(f"service must not be called: {kwargs}")

    monkeypatch.setattr(v2_rbac, "OperatingRoleAssignmentService", _OperatingRoles)
    response = client.put(
        "/security/v1/tenants/00000000-0000-0000-0000-000000000099/"
        "users/00000000-0000-0000-0000-000000000030/operating-role",
        json={"roleKey": "PC"},
    )

    assert response.status_code == 403
    assert response.json()["code"] == "PERMISSION_DENIED"


def test_only_super_admin_can_replace_tenant_role_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tenant_id = "00000000-0000-0000-0000-000000000010"
    _use_actor(_actor(AdminScope("TenantAdmin", "TENANT", tenant_id)))

    class _Bundles:
        def __init__(self, session: object) -> None:
            _ = session

        def replace_tenant_bundle(self, **kwargs: object) -> list[str]:
            raise AssertionError(f"service must not be called: {kwargs}")

    monkeypatch.setattr(v2_rbac, "TenantRoleBundleService", _Bundles)
    denied = client.put(
        f"/security/v1/tenants/{tenant_id}/role-bundles/PC",
        json={"permissions": ["security.tenant.read"]},
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "PERMISSION_DENIED"

    super_admin = _actor(AdminScope("SuperAdmin", "PLATFORM", None))
    _use_actor(super_admin)
    observed: dict[str, object] = {}

    class _SuperAdminBundles:
        def __init__(self, session: object) -> None:
            _ = session

        def replace_tenant_bundle(self, **kwargs: object) -> list[str]:
            observed.update(kwargs)
            return ["security.tenant.read"]

    monkeypatch.setattr(v2_rbac, "TenantRoleBundleService", _SuperAdminBundles)
    allowed = client.put(
        f"/security/v1/tenants/{tenant_id}/role-bundles/PC",
        json={"permissions": ["security.tenant.read"]},
        headers={"X-Correlation-ID": "bundle-change"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["permissions"] == ["security.tenant.read"]
    assert observed["actor_user_id"] == super_admin.user_id
    assert observed["correlation_id"] == "bundle-change"


def test_platform_defaults_are_super_admin_only(monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = "00000000-0000-0000-0000-000000000010"
    _use_actor(_actor(AdminScope("TenantAdmin", "TENANT", tenant_id)))

    class _Bundles:
        def __init__(self, session: object) -> None:
            _ = session

        def platform_default(self, role_key: str) -> list[str]:
            raise AssertionError(f"service must not be called for {role_key}")

    monkeypatch.setattr(v2_rbac, "TenantRoleBundleService", _Bundles)
    denied = client.get("/security/v1/platform/role-defaults/PC")
    assert denied.status_code == 403

    _use_actor(_actor(AdminScope("SuperAdmin", "PLATFORM", None)))

    class _SuperAdminBundles:
        def __init__(self, session: object) -> None:
            _ = session

        def platform_default(self, role_key: str) -> list[str]:
            assert role_key == "PC"
            return ["security.tenant.read"]

    monkeypatch.setattr(v2_rbac, "TenantRoleBundleService", _SuperAdminBundles)
    allowed = client.get("/security/v1/platform/role-defaults/PC")
    assert allowed.status_code == 200
    assert allowed.json() == {
        "roleKey": "PC",
        "permissions": ["security.tenant.read"],
    }
