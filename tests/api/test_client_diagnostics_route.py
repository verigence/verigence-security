from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import client_diagnostics
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


def _service(monkeypatch: pytest.MonkeyPatch, *, enabled: bool = False) -> list[tuple[Any, ...]]:
    calls: list[tuple[Any, ...]] = []

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def enabled(self) -> bool:
            return enabled

        def set_enabled(self, *, enabled: bool, actor_user_id: str, correlation_id: str) -> None:
            calls.append(("set", enabled))

        def accept(self, **kw: Any) -> bool:
            calls.append(("accept", kw["device_id"], len(kw["entries"])))
            return enabled

        def listing(self) -> list[dict[str, Any]]:
            return [{"logId": "l1"}]

        def clear(self, *, actor_user_id: str, correlation_id: str) -> int:
            calls.append(("clear",))
            return 3

    monkeypatch.setattr(client_diagnostics, "ClientDiagnosticsService", _Service)
    return calls


ENTRY = {"time": "2026-10-05T09:00:00Z", "step": "bootstrap.cold-start", "detail": {"deviceType": "android"}}


def test_the_app_is_told_diagnostics_are_off_unless_switched_on(monkeypatch: pytest.MonkeyPatch) -> None:
    _as()
    _service(monkeypatch)
    assert client.get("/security/v1/me/client-diagnostics").json() == {"enabled": False}
    _service(monkeypatch, enabled=True)
    assert client.get("/security/v1/me/client-diagnostics").json() == {"enabled": True}


def test_a_signed_in_app_sends_its_log_and_is_told_whether_it_was_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    _as()
    calls = _service(monkeypatch, enabled=True)
    body = {"deviceId": "device-1234", "platform": "android", "appVersion": "1.4", "entries": [ENTRY]}
    assert client.post("/security/v1/me/client-diagnostics/logs", json=body).json() == {"accepted": True}
    assert calls == [("accept", "device-1234", 1)]


@pytest.mark.parametrize(
    "body",
    [
        {"deviceId": "short", "entries": [ENTRY]},
        {"deviceId": "device-1234", "entries": [{**ENTRY, "step": "x" * 121}]},
        {"deviceId": "device-1234", "entries": [ENTRY] * 101},
        {"deviceId": "device-1234", "entries": [ENTRY], "extra": 1},
    ],
)
def test_bad_uploads_are_refused(monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]) -> None:
    _as()
    calls = _service(monkeypatch, enabled=True)
    assert client.post("/security/v1/me/client-diagnostics/logs", json=body).status_code == 422
    assert calls == []


def test_super_admin_switches_it_on_reads_the_logs_and_clears_them(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    assert client.get("/security/v1/admin/client-diagnostics").json() == {"enabled": False, "logs": [{"logId": "l1"}]}
    assert client.put("/security/v1/admin/client-diagnostics", json={"enabled": True}).json() == {"enabled": True}
    assert client.delete("/security/v1/admin/client-diagnostics/logs").json() == {"removed": 3}
    assert calls == [("set", True), ("clear",)]


def test_only_super_admin_manages_it(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("TenantAdmin", "TENANT", "t1"))
    calls = _service(monkeypatch)
    assert client.get("/security/v1/admin/client-diagnostics").status_code == 403
    assert client.put("/security/v1/admin/client-diagnostics", json={"enabled": True}).status_code == 403
    assert client.delete("/security/v1/admin/client-diagnostics/logs").status_code == 403
    assert calls == []
