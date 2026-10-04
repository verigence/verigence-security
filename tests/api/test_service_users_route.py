from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from verigence_security.adapters.clerk_backend import ClerkBackendError
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.routes import service_users
from verigence_security.core.errors import security_error
from verigence_security.main import app
from verigence_security.services.v2_platform_user_create import CreatedUser, InvalidUserInput

client = TestClient(app)
USER = "00000000-0000-4000-8000-000000000020"
PRINCIPAL = "00000000-0000-4000-8000-0000000000aa"
BODY = {
    "firstName": "Sample",
    "lastName": "Person",
    "email": "sample@example.test",
    "mobile": "9000000001",
    "password": "transient-secret",
}
AUTH = {"Authorization": "Bearer service-token"}


class _Result:
    def __init__(self, row: object) -> None:
        self._row = row

    def first(self) -> object:
        return self._row


class _Session:
    """Answers the single integration lookup the route makes."""

    def __init__(self, principal: str | None) -> None:
        self.principal = principal

    def execute(self, *_: object, **__: object) -> _Result:
        return _Result((self.principal,) if self.principal else None)


@pytest.fixture(autouse=True)
def _reset(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setattr(service_users, "ClerkBackendClient", lambda settings: object())
    yield
    app.dependency_overrides.clear()


def _caller(monkeypatch: pytest.MonkeyPatch, *, subject: str = "hrmgmt", principal: str | None = PRINCIPAL) -> None:
    class _Tokens:
        def __init__(self, settings: object) -> None:
            _ = settings

        def verify_service_token(self, token: str, *, audience: str) -> dict[str, object]:
            assert token == "service-token" and audience == "security"
            return {"sub": subject}

    monkeypatch.setattr(service_users, "TokenService", _Tokens)
    app.dependency_overrides[platform_session] = lambda: _Session(principal)


def _create_service(monkeypatch: pytest.MonkeyPatch, outcome: object = None) -> list[dict[str, object]]:
    calls: list[dict[str, object]] = []

    class _Service:
        def __init__(self, session: object) -> None:
            _ = session

        def create_for_service(self, **kwargs: object) -> CreatedUser:
            calls.append(kwargs)
            if isinstance(outcome, Exception):
                raise outcome
            return CreatedUser(user_id=USER, clerk_subject="user_new")

    class _Directory:
        def __init__(self, session: object) -> None:
            _ = session

        def get_user(self, user_id: str) -> dict[str, object]:
            now = datetime.now(UTC)
            return {
                "user_id": user_id, "display_name": "Sample Person", "primary_email": "sample@example.test",
                "primary_mobile": "+919000000001", "status": "ACTIVE", "clerk_subject": "user_new",
                "onboarding_status": None, "created_at_utc": now, "updated_at_utc": now,
            }

    monkeypatch.setattr(service_users, "V2PlatformUserCreateService", _Service)
    monkeypatch.setattr(service_users, "V2UserDirectoryService", _Directory)
    return calls


def test_allowed_integration_creates_a_user_through_the_service(monkeypatch: pytest.MonkeyPatch) -> None:
    _caller(monkeypatch)
    calls = _create_service(monkeypatch)
    response = client.post("/security/v1/service/users", json=BODY, headers=AUTH)
    assert response.status_code == 201
    assert response.json()["status"] == "ACTIVE" and response.json()["userId"] == USER
    assert calls[0]["password"] == "transient-secret"
    assert calls[0]["service_principal_id"] == PRINCIPAL and calls[0]["service_integration_key"] == "hrmgmt"
    assert "transient-secret" not in response.text


def test_other_integrations_are_refused_even_with_a_valid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _caller(monkeypatch, subject="audit-core")
    calls = _create_service(monkeypatch)
    assert client.post("/security/v1/service/users", json=BODY, headers=AUTH).status_code == 403
    assert calls == []


def test_unknown_or_inactive_integration_is_unauthenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    _caller(monkeypatch, principal=None)
    calls = _create_service(monkeypatch)
    assert client.post("/security/v1/service/users", json=BODY, headers=AUTH).status_code == 401
    assert calls == []


def test_missing_or_invalid_token_is_unauthenticated(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _create_service(monkeypatch)
    app.dependency_overrides[platform_session] = lambda: _Session(PRINCIPAL)
    assert client.post("/security/v1/service/users", json=BODY).status_code == 401

    class _Reject:
        def __init__(self, settings: object) -> None:
            _ = settings

        def verify_service_token(self, token: str, *, audience: str) -> dict[str, object]:
            raise security_error("AUTH_TOKEN_INVALID")

    monkeypatch.setattr(service_users, "TokenService", _Reject)
    assert client.post("/security/v1/service/users", json=BODY, headers=AUTH).status_code == 401
    assert calls == []


def test_allow_list_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    from verigence_security.config import Settings, get_settings

    _caller(monkeypatch, subject="someone-else")
    calls = _create_service(monkeypatch)
    app.dependency_overrides[get_settings] = lambda: Settings(service_user_create_integrations="hrmgmt, someone-else")
    assert client.post("/security/v1/service/users", json=BODY, headers=AUTH).status_code == 201
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (InvalidUserInput("A valid 10-digit Indian mobile number is required"), 422),
        (ValueError("Email address belongs to an active or suspended user"), 409),
        (ClerkBackendError("create", status_code=422, provider_code="form_identifier_exists"), 409),
        (ClerkBackendError("create", status_code=503), 503),
    ],
)
def test_failures_map_to_actionable_statuses(monkeypatch: pytest.MonkeyPatch, error: Exception, status: int) -> None:
    _caller(monkeypatch)
    _create_service(monkeypatch, error)
    response = client.post("/security/v1/service/users", json=BODY, headers=AUTH)
    assert response.status_code == status
    assert "transient-secret" not in response.text


class _LookupSession:
    """First query: the integration check. Second: the user lookup."""

    def __init__(self, principal: str | None, user: tuple[str, str, str] | None) -> None:
        self.principal, self.user, self.calls = principal, user, 0

    def execute(self, *_: object, **__: object) -> _Result:
        self.calls += 1
        if self.calls == 1:
            return _Result((self.principal,) if self.principal else None)
        return _Result(self.user)


def _lookup_caller(monkeypatch: pytest.MonkeyPatch, user: tuple[str, str, str] | None, subject: str = "hrmgmt") -> None:
    _caller(monkeypatch, subject=subject)
    app.dependency_overrides[platform_session] = lambda: _LookupSession(PRINCIPAL, user)


def test_allowed_integration_finds_an_existing_user_by_email(monkeypatch: pytest.MonkeyPatch) -> None:
    _lookup_caller(monkeypatch, (USER, "Sample Person", "ACTIVE"))
    response = client.get("/security/v1/service/users/lookup", params={"email": " Sample@Example.test "}, headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {"userId": USER, "displayName": "Sample Person", "status": "ACTIVE"}


def test_lookup_without_a_match_is_404(monkeypatch: pytest.MonkeyPatch) -> None:
    _lookup_caller(monkeypatch, None)
    response = client.get("/security/v1/service/users/lookup", params={"email": "nobody@example.test"}, headers=AUTH)
    assert response.status_code == 404


def test_lookup_is_refused_for_other_integrations_and_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _lookup_caller(monkeypatch, (USER, "Sample Person", "ACTIVE"), subject="audit-core")
    params = {"email": "sample@example.test"}
    assert client.get("/security/v1/service/users/lookup", params=params, headers=AUTH).status_code == 403
    assert client.get("/security/v1/service/users/lookup", params=params).status_code == 401


class _FlagSession:
    """First query: the integration check. Second: the flag update."""

    def __init__(self, found: bool) -> None:
        self.found, self.calls, self.committed = found, 0, False

    def execute(self, *_: object, **__: object) -> _Result:
        self.calls += 1
        if self.calls == 1:
            return _Result((PRINCIPAL,))
        return _Result((1,) if self.found else None)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        pass


def test_allowed_integration_can_tick_is_employee(monkeypatch: pytest.MonkeyPatch) -> None:
    _caller(monkeypatch)
    session = _FlagSession(True)
    app.dependency_overrides[platform_session] = lambda: session
    response = client.post(f"/security/v1/service/users/{USER}/employee", headers=AUTH)
    assert response.status_code == 200 and response.json() == {"userId": USER, "isEmployee": True}
    assert session.committed


def test_ticking_is_employee_for_an_unknown_user_is_404_and_other_integrations_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _caller(monkeypatch)
    app.dependency_overrides[platform_session] = lambda: _FlagSession(False)
    assert client.post(f"/security/v1/service/users/{USER}/employee", headers=AUTH).status_code == 404
    _caller(monkeypatch, subject="audit-core")
    app.dependency_overrides[platform_session] = lambda: _FlagSession(True)
    assert client.post(f"/security/v1/service/users/{USER}/employee", headers=AUTH).status_code == 403
