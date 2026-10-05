from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import login_activity
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)


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

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def record_download(self, *, user_id: str, app_version: str | None, source_ip: str | None) -> None:
            calls.append(("download", user_id, app_version))

        def report(self) -> dict[str, Any]:
            calls.append(("report",))
            return {"people": [], "unknown": []}

    monkeypatch.setattr(login_activity, "LoginActivityService", _Service)
    return calls


def test_a_signed_in_person_records_an_app_download(monkeypatch: pytest.MonkeyPatch) -> None:
    _as()
    calls = _service(monkeypatch)
    response = client.post("/security/v1/me/app-download", json={"appVersion": "1.4"})
    assert response.json() == {"recorded": True}
    assert calls == [("download", "00000000-0000-4000-8000-000000000001", "1.4")]


def test_only_super_admin_reads_the_report(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("TenantAdmin", "TENANT", "t1"))
    calls = _service(monkeypatch)
    assert client.get("/security/v1/admin/login-activity").status_code == 403
    assert calls == []
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    assert client.get("/security/v1/admin/login-activity").json() == {"people": [], "unknown": []}
    assert calls == [("report",)]
