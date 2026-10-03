from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import hr_roles
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)
USER = "00000000-0000-4000-8000-000000000020"


@pytest.fixture(autouse=True)
def _overrides() -> Iterator[None]:
    app.dependency_overrides[platform_session] = lambda: object()
    yield
    app.dependency_overrides.clear()


def _as(*scopes: AdminScope) -> None:
    actor = HumanActorContext(user_id="00000000-0000-4000-8000-000000000001", clerk_subject="u",
                              admin_scopes=tuple(scopes))
    app.dependency_overrides[security_human_actor] = lambda: actor


def _service(monkeypatch: pytest.MonkeyPatch, error: Exception | None = None) -> list[tuple[str, str, str]]:
    calls: list[tuple[str, str, str]] = []

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def assign(self, *, user_id: str, role_key: str, actor_user_id: str, correlation_id: str):
            calls.append(("assign", user_id, role_key))
            if error:
                raise error
            return True, "assignment-1"

        def remove(self, *, user_id: str, role_key: str, actor_user_id: str, correlation_id: str):
            calls.append(("remove", user_id, role_key))
            return True, "assignment-1"

    monkeypatch.setattr(hr_roles, "HrModuleRoleService", _Service)
    return calls


@pytest.mark.parametrize("role", ["HRADMIN", "FINANCEADMIN", "CEO"])
def test_super_admin_assigns_and_removes_each_hr_role(monkeypatch: pytest.MonkeyPatch, role: str) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    put = client.put(f"/security/v1/users/{USER}/module-roles/hr/{role}")
    assert put.status_code == 200 and put.json()["roleKey"] == role and put.json()["moduleKey"] == "hr"
    assert client.delete(f"/security/v1/users/{USER}/module-roles/hr/{role}").status_code == 200
    assert calls == [("assign", USER, role), ("remove", USER, role)]


def test_only_super_admin_may_manage_hr_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("TenantAdmin", "TENANT", "t1"))
    calls = _service(monkeypatch)
    assert client.put(f"/security/v1/users/{USER}/module-roles/hr/CEO").status_code == 403
    assert client.delete(f"/security/v1/users/{USER}/module-roles/hr/CEO").status_code == 403
    assert calls == []


def test_unknown_role_is_rejected_before_anything_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    assert client.put(f"/security/v1/users/{USER}/module-roles/hr/ROOT").status_code == 422
    assert calls == []


def test_conflicts_are_409(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    _service(monkeypatch, ValueError("The HR role subject must be an active Verigence USER"))
    assert client.put(f"/security/v1/users/{USER}/module-roles/hr/HRADMIN").status_code == 409
