from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from verigence_security.adapters.clerk_backend import ClerkBackendError
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import v2_user_admin
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.main import app
from verigence_security.services.v2_human_actor import AdminScope, HumanActorContext
from verigence_security.services.v2_platform_user_create import CreatedUser, InvalidUserInput

client = TestClient(app)
USER = "00000000-0000-4000-8000-000000000020"
BODY = {"firstName": "Sample", "lastName": "Person", "email": "sample@example.test", "mobile": "9000000001",
        "password": "transient"}


@pytest.fixture(autouse=True)
def _overrides(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    app.dependency_overrides[platform_session] = lambda: object()
    monkeypatch.setattr(v2_user_admin, "ClerkBackendClient", lambda settings: object())
    yield
    app.dependency_overrides.clear()


def _as(*scopes: AdminScope) -> None:
    actor = HumanActorContext(user_id="00000000-0000-4000-8000-000000000001", clerk_subject="user_a",
                              admin_scopes=tuple(scopes))
    app.dependency_overrides[security_human_actor] = lambda: actor


def _service(monkeypatch: pytest.MonkeyPatch, outcome: object) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def create(self, **kwargs: object) -> CreatedUser:
            calls.append(kwargs)
            if isinstance(outcome, Exception):
                raise outcome
            return CreatedUser(user_id=USER, clerk_subject="user_new")

    class _Directory:
        def __init__(self, session: object) -> None:
            _ = session

        def get_user(self, user_id: str) -> dict[str, object]:
            now = datetime.now(UTC)
            return {"user_id": user_id, "display_name": "Sample Person", "primary_email": "sample@example.test",
                    "primary_mobile": "+919000000001", "status": "ACTIVE", "clerk_subject": "user_new",
                    "onboarding_status": None, "created_at_utc": now, "updated_at_utc": now}

    monkeypatch.setattr(v2_user_admin, "V2PlatformUserCreateService", _Service)
    monkeypatch.setattr(v2_user_admin, "V2UserDirectoryService", _Directory)
    return calls


def test_super_admin_creates_an_active_user(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    calls = _service(monkeypatch, None)
    response = client.post("/security/v1/platform/users", json=BODY)
    assert response.status_code == 201
    assert response.json()["status"] == "ACTIVE" and response.json()["userId"] == USER
    assert calls[0]["password"] == "transient"
    assert "transient" not in response.text


def test_only_super_admin_may_create(monkeypatch: pytest.MonkeyPatch) -> None:
    _as(AdminScope("TenantAdmin", "TENANT", "t1"))
    calls = _service(monkeypatch, None)
    assert client.post("/security/v1/platform/users", json=BODY).status_code == 403
    assert calls == []


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (InvalidUserInput("A valid 10-digit Indian mobile number is required"), 422),
        (ValueError("Email address belongs to an active or suspended user"), 409),
        (ClerkBackendError("create", status_code=422, provider_code="form_password_pwned",
                           provider_detail="Password has been found in an online data breach."), 422),
        (ClerkBackendError("create", status_code=422, provider_code="form_identifier_exists"), 409),
        (ClerkBackendError("create", status_code=503), 503),
    ],
)
def test_failures_map_to_actionable_statuses(
    monkeypatch: pytest.MonkeyPatch, error: Exception, status: int
) -> None:
    _as(AdminScope("SuperAdmin", "PLATFORM", None))
    _service(monkeypatch, error)
    response = client.post("/security/v1/platform/users", json=BODY)
    assert response.status_code == status
