from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import feature_access
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
    actor = HumanActorContext(
        user_id="00000000-0000-4000-8000-000000000001", clerk_subject="u", admin_scopes=tuple(scopes)
    )
    app.dependency_overrides[security_human_actor] = lambda: actor


def _service(monkeypatch: pytest.MonkeyPatch) -> list[tuple[object, ...]]:
    calls: list[tuple[object, ...]] = []

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def resolve(self, *, user_id: str, is_super_admin: bool) -> dict[str, bool]:
            calls.append(("resolve", user_id, is_super_admin))
            return {"AUDIT": is_super_admin, "ANALYTICS": False}

        def overview(self) -> list[dict[str, object]]:
            calls.append(("overview",))
            return [{"featureKey": "AUDIT", "everyone": False, "people": []}]

        def set_everyone(self, *, feature_key: str, enabled: bool, actor_user_id: str, correlation_id: str) -> None:
            calls.append(("everyone", feature_key, enabled))

        def set_person(
            self, *, feature_key: str, user_id: str, enabled: bool | None, actor_user_id: str, correlation_id: str
        ) -> None:
            calls.append(("person", feature_key, user_id, enabled))

    monkeypatch.setattr(feature_access, "FeatureAccessService", _Service)
    return calls


def test_anyone_signed_in_reads_their_own_features(monkeypatch: pytest.MonkeyPatch) -> None:
    _as()
    calls = _service(monkeypatch)
    r = client.get("/security/v1/me/features")
    assert r.status_code == 200 and r.json() == {"features": {"AUDIT": False, "ANALYTICS": False}}
    assert calls[0][0] == "resolve" and calls[0][2] is False


def test_super_admin_manages_features(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    assert client.get("/security/v1/admin/features").status_code == 200
    assert client.put("/security/v1/admin/features/AUDIT/everyone", json={"enabled": True}).status_code == 200
    assert client.put(f"/security/v1/admin/features/ANALYTICS/users/{USER}", json={"enabled": None}).status_code == 200
    assert calls == [("overview",), ("everyone", "AUDIT", True), ("person", "ANALYTICS", USER, None)]


def test_only_super_admin_may_change_features(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("TenantAdmin", "TENANT", "t1"))
    calls = _service(monkeypatch)
    assert client.get("/security/v1/admin/features").status_code == 403
    assert client.put("/security/v1/admin/features/AUDIT/everyone", json={"enabled": True}).status_code == 403
    assert client.put(f"/security/v1/admin/features/AUDIT/users/{USER}", json={"enabled": True}).status_code == 403
    assert calls == []


def test_unknown_feature_and_extra_fields_are_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    assert client.put("/security/v1/admin/features/PAYROLL/everyone", json={"enabled": True}).status_code == 422
    assert client.put("/security/v1/admin/features/AUDIT/everyone", json={"enabled": True, "x": 1}).status_code == 422
    assert calls == []
