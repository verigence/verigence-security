"""The SuperAdmin routes for the minimum app version of one Project (product owner, 19 Nov 2026)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import app_version as route
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.app_version_policy import Policy, ProjectPolicy
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)
MAHINDRA = "00000000-0000-4000-8000-0000000000a1"
BASE = "/security/v1/admin/app-version-policy"


@pytest.fixture(autouse=True)
def _overrides() -> Iterator[None]:
    app.dependency_overrides[platform_session] = lambda: object()
    yield
    app.dependency_overrides.clear()


def _as(*scopes: AdminScope) -> None:
    actor = HumanActorContext(
        user_id="00000000-0000-4000-8000-000000000001", clerk_subject="u", admin_scopes=tuple(scopes)
    )
    app.dependency_overrides[security_human_actor] = lambda: actor


def _service(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []
    projects: list[ProjectPolicy] = []

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def policy(self) -> Policy:
            return Policy("1.7.0", None, "https://example.test/apps")

        def devices_below(self, minimum_version: str | None) -> list[dict[str, Any]]:
            return []

        def project_policies(self) -> list[ProjectPolicy]:
            return list(projects)

        def project_choices(self) -> list[dict[str, Any]]:
            return [{"tenantId": MAHINDRA, "tenantName": "Mahindra Orissa", "people": 17}]

        def project_devices_below(self, tenant_id: str, minimum_version: str | None) -> list[dict[str, Any]]:
            calls.append(("impact", tenant_id, minimum_version))
            return [{"appVersion": "1.7.0", "devices": 12, "people": 12}]

        def set_project_policy(
            self,
            *,
            tenant_id: str,
            minimum_version: str | None,
            effective_from: datetime | None,
            actor_user_id: str,
            correlation_id: str,
        ) -> list[ProjectPolicy]:
            calls.append(("set", tenant_id, minimum_version, effective_from))
            if tenant_id != MAHINDRA:
                raise LookupError("Project not found")
            projects.clear()
            if minimum_version is not None:
                projects.append(ProjectPolicy(tenant_id, "Mahindra Orissa", minimum_version, effective_from))
            return list(projects)

    monkeypatch.setattr(route, "AppVersionPolicyService", _Service)
    return calls


def test_superadmin_sets_sees_and_removes_the_minimum_of_one_project(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    before = client.get(BASE).json()
    assert before["minimumVersion"] == "1.7.0" and before["projects"] == []
    assert before["projectChoices"] == [{"tenantId": MAHINDRA, "tenantName": "Mahindra Orissa", "people": 17}]

    impact = client.get(f"{BASE}/projects/{MAHINDRA}/impact?minimumVersion=1.9.0")
    assert impact.json() == {"devicesBelow": [{"appVersion": "1.7.0", "devices": 12, "people": 12}]}

    saved = client.put(f"{BASE}/projects/{MAHINDRA}", json={"minimumVersion": "1.9.0"})
    assert saved.status_code == 200
    [project] = saved.json()["projects"]
    assert (project["tenantName"], project["minimumVersion"], project["inForce"]) == ("Mahindra Orissa", "1.9.0", True)
    assert project["devicesBelow"] == [{"appVersion": "1.7.0", "devices": 12, "people": 12}]
    # The minimum for everyone is as it was.
    assert saved.json()["minimumVersion"] == "1.7.0"

    later = client.put(
        f"{BASE}/projects/{MAHINDRA}", json={"minimumVersion": "1.9.0", "effectiveFrom": "2099-01-01T14:30:00Z"}
    )
    assert later.json()["projects"][0]["inForce"] is False
    assert ("set", MAHINDRA, "1.9.0", datetime(2099, 1, 1, 14, 30, tzinfo=UTC)) in calls

    removed = client.put(f"{BASE}/projects/{MAHINDRA}", json={"minimumVersion": None})
    assert removed.status_code == 200 and removed.json()["projects"] == []


def test_only_superadmin_and_only_a_real_project_and_version(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _service(monkeypatch)
    _as()
    assert client.put(f"{BASE}/projects/{MAHINDRA}", json={"minimumVersion": "1.9.0"}).status_code == 403
    assert client.get(f"{BASE}/projects/{MAHINDRA}/impact?minimumVersion=1.9.0").status_code == 403
    assert calls == []
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    assert client.put(f"{BASE}/projects/{MAHINDRA}", json={"minimumVersion": "1.9"}).status_code == 422
    assert client.put(f"{BASE}/projects/not-a-project", json={"minimumVersion": "1.9.0"}).status_code == 422
    unknown = "00000000-0000-4000-8000-0000000000ff"
    assert client.put(f"{BASE}/projects/{unknown}", json={"minimumVersion": "1.9.0"}).status_code == 404
