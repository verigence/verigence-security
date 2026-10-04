from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import announcements
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext

client = TestClient(app)
ID = "00000000-0000-4000-8000-000000000030"


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

        def maintenance(self) -> dict[str, Any] | None:
            calls.append(("maintenance",))
            return {"announcementId": ID, "kind": "MAINTENANCE", "title": "Back soon", "body": "x"}

        def next_for(self, *, user_id: str) -> None:
            calls.append(("next", user_id))

        def mark_seen(self, *, announcement_id: str, user_id: str) -> None:
            calls.append(("seen", announcement_id))

        def listing(self) -> list[dict[str, Any]]:
            return [{"announcementId": ID, "audience": "EVERYONE"}]

        def people_of(self, announcement_id: str) -> list[dict[str, Any]]:
            return []

        def quiet_hours(self) -> int:
            return 20

        def set_quiet_hours(self, *, hours: int, actor_user_id: str, correlation_id: str) -> None:
            calls.append(("quiet", hours))

        def create(self, **kw: Any) -> str:
            calls.append(("create", kw["kind"], kw["audience"]))
            return ID

        def update(self, **kw: Any) -> None:
            calls.append(("update", kw["announcement_id"], kw["active"]))

    monkeypatch.setattr(announcements, "AnnouncementService", _Service)
    return calls


def test_the_maintenance_state_needs_no_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _service(monkeypatch)
    r = client.get("/security/v1/status/maintenance")
    assert r.status_code == 200 and r.json()["maintenance"]["title"] == "Back soon"
    assert calls == [("maintenance",)]


def test_a_person_reads_and_dismisses_their_own_announcement(monkeypatch: pytest.MonkeyPatch) -> None:
    _as()
    calls = _service(monkeypatch)
    assert client.get("/security/v1/me/announcements").json() == {"announcement": None}
    assert client.post(f"/security/v1/me/announcements/{ID}/seen").status_code == 200
    assert [c[0] for c in calls] == ["next", "seen"]


def test_super_admin_manages_announcements_and_the_wait_between_them(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    assert client.get("/security/v1/admin/announcements").status_code == 200
    assert client.get("/security/v1/admin/announcements/settings").json() == {"quietHours": 20}
    assert client.put("/security/v1/admin/announcements/settings", json={"quietHours": 0}).status_code == 200
    body = {"kind": "NOTICE", "title": "Hello", "body": "Welcome to Verigence"}
    assert client.post("/security/v1/admin/announcements", json=body).status_code == 201
    assert client.patch(f"/security/v1/admin/announcements/{ID}", json={"active": False}).status_code == 200
    assert calls == [("quiet", 0), ("create", "NOTICE", "EVERYONE"), ("update", ID, False)]


def test_only_super_admin_manages_announcements(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("TenantAdmin", "TENANT", "t1"))
    calls = _service(monkeypatch)
    body = {"kind": "NOTICE", "title": "Hello", "body": "x"}
    assert client.get("/security/v1/admin/announcements").status_code == 403
    assert client.post("/security/v1/admin/announcements", json=body).status_code == 403
    assert client.patch(f"/security/v1/admin/announcements/{ID}", json={"active": False}).status_code == 403
    assert client.put("/security/v1/admin/announcements/settings", json={"quietHours": 1}).status_code == 403
    assert calls == []


@pytest.mark.parametrize(
    "body",
    [
        {"kind": "NOTICE", "title": "", "body": "x"},
        {"kind": "NOTICE", "title": "t", "body": "x" * 1001},
        {"kind": "LOUD", "title": "t", "body": "x"},
        {"kind": "NOTICE", "title": "t", "body": "x", "extra": 1},
    ],
)
def test_bad_announcements_are_refused(monkeypatch: pytest.MonkeyPatch, body: dict[str, Any]) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch)
    assert client.post("/security/v1/admin/announcements", json=body).status_code == 422
    assert calls == []
