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


class _PasswordSession:
    """First query: the integration check. Second: the user row."""

    def __init__(self, row: tuple[str, str | None, str | None] | None) -> None:
        self.row, self.calls = row, 0

    def execute(self, *_: object, **__: object) -> _Result:
        self.calls += 1
        if self.calls == 1:
            return _Result((PRINCIPAL,))
        return _Result(self.row)

    def rollback(self) -> None:
        pass


def _fake_clerk(monkeypatch: pytest.MonkeyPatch, *, confirms: bool) -> None:
    class _Clerk:
        def verify_password(self, **_: object) -> bool:
            return confirms

    monkeypatch.setattr(service_users, "ClerkBackendClient", lambda settings: _Clerk())


def _password_caller(
    monkeypatch: pytest.MonkeyPatch, row: tuple[str, str | None, str | None] | None
) -> list[tuple[str, str]]:
    _caller(monkeypatch)
    app.dependency_overrides[platform_session] = lambda: _PasswordSession(row)
    set_calls: list[tuple[str, str]] = []
    _fake_clerk(monkeypatch, confirms=True)
    monkeypatch.setattr(
        service_users,
        "update_password",
        lambda clerk, *, clerk_user_id, password: set_calls.append((clerk_user_id, password)),
    )
    return set_calls


def test_allowed_integration_sets_a_password_for_an_active_user(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _password_caller(monkeypatch, ("ACTIVE", "emp@example.test", "user_clerk_1"))
    response = client.post(
        f"/security/v1/service/users/{USER}/password", json={"password": "Temp-Pass-123"}, headers=AUTH
    )
    assert response.status_code == 200
    assert response.json() == {"userId": USER, "primaryEmail": "emp@example.test"}
    assert calls == [("user_clerk_1", "Temp-Pass-123")]
    assert "Temp-Pass-123" not in response.text


def test_a_password_the_provider_does_not_confirm_is_still_reported_set_so_hr_is_never_blocked(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _password_caller(monkeypatch, ("ACTIVE", "emp@example.test", "user_clerk_1"))
    _fake_clerk(monkeypatch, confirms=False)
    response = client.post(
        f"/security/v1/service/users/{USER}/password", json={"password": "Temp-Pass-123"}, headers=AUTH
    )
    assert response.status_code == 200
    assert "Temp-Pass-123" not in response.text and "Temp-Pass-123" not in caplog.text
    assert "set_password_not_confirmed" in caplog.text


def test_a_password_is_refused_for_a_user_who_is_not_active(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _password_caller(monkeypatch, ("PENDING", "emp@example.test", "user_clerk_1"))
    response = client.post(
        f"/security/v1/service/users/{USER}/password", json={"password": "Temp-Pass-123"}, headers=AUTH
    )
    assert response.status_code == 409 and calls == []


def test_password_for_an_unknown_user_is_404_and_other_integrations_are_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _password_caller(monkeypatch, None)
    body = {"password": "Temp-Pass-123"}
    assert client.post(f"/security/v1/service/users/{USER}/password", json=body, headers=AUTH).status_code == 404
    _caller(monkeypatch, subject="audit-core")
    app.dependency_overrides[platform_session] = lambda: _PasswordSession(("ACTIVE", "e@x.test", "c"))
    assert client.post(f"/security/v1/service/users/{USER}/password", json=body, headers=AUTH).status_code == 403
    assert calls == []


class _ListSession:
    def __init__(self, rows: list[tuple[str, str, str, str, bool]]) -> None:
        self.rows, self.calls, self.params = rows, 0, {}

    def execute(self, _sql: object, params: dict[str, object] | None = None) -> object:
        self.calls += 1
        if self.calls == 1:
            return _Result((PRINCIPAL,))
        self.params = params or {}

        class _All:
            def __init__(self, rows: list[tuple[str, str, str, str, bool]]) -> None:
                self._rows = rows

            def all(self) -> list[tuple[str, str, str, str, bool]]:
                return self._rows

        return _All(self.rows)

    def rollback(self) -> None:
        pass


def test_allowed_integration_lists_users_with_only_the_agreed_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    _caller(monkeypatch)
    session = _ListSession([(USER, "Sample Person", "sample@example.test", "ACTIVE", True)])
    app.dependency_overrides[platform_session] = lambda: session
    response = client.get("/security/v1/service/users", params={"q": " Sample ", "ids": f"{USER},x"}, headers=AUTH)
    assert response.status_code == 200
    assert response.json() == [
        {
            "userId": USER,
            "displayName": "Sample Person",
            "primaryEmail": "sample@example.test",
            "status": "ACTIVE",
            "isEmployee": True,
        }
    ]
    assert session.params["pattern"] == "%sample%" and session.params["ids"] == [USER, "x"]


def test_listing_users_is_refused_for_other_integrations_and_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    _caller(monkeypatch, subject="audit-core")
    app.dependency_overrides[platform_session] = lambda: _ListSession([])
    assert client.get("/security/v1/service/users", headers=AUTH).status_code == 403
    assert client.get("/security/v1/service/users").status_code == 401


def test_employee_sync_reports_each_user_and_needs_the_service_guard(monkeypatch: pytest.MonkeyPatch) -> None:
    from verigence_security.services.v2_user_lifecycle import EmployeeSyncOutcome

    seen: list[tuple[str, bool]] = []

    class _Lifecycle:
        def __init__(self, session: object) -> None:
            _ = session

        def sync_employee_for_service(self, **kw: object) -> EmployeeSyncOutcome:
            seen.append((str(kw["user_id"]), bool(kw["suspend"])))
            assert kw["principal_id"] == PRINCIPAL and kw["integration_key"] == "hrmgmt"
            if kw["user_id"] == "boom":
                raise RuntimeError("db")
            return EmployeeSyncOutcome(str(kw["user_id"]), True, "SUSPENDED", True, True, bool(kw["suspend"]), None)

    _caller(monkeypatch)
    app.dependency_overrides[platform_session] = lambda: _PasswordSession(None)
    monkeypatch.setattr(service_users, "V2UserLifecycleService", _Lifecycle)
    body = {"items": [{"userId": USER, "suspend": True}, {"userId": "boom"}]}
    response = client.post("/security/v1/service/users/employee-sync", json=body, headers=AUTH)
    assert response.status_code == 200
    rows = response.json()
    assert rows[0] == {"userId": USER, "found": True, "status": "SUSPENDED", "isEmployee": True,
                       "ticked": True, "suspended": True, "note": None}
    assert rows[1]["note"] == "NOT_PROCESSED" and rows[1]["found"] is False
    assert seen == [(USER, True), ("boom", False)]
    _caller(monkeypatch, subject="audit-core")
    assert client.post("/security/v1/service/users/employee-sync", json=body, headers=AUTH).status_code == 403
    assert client.post("/security/v1/service/users/employee-sync", json={"items": []}, headers=AUTH).status_code == 422


def _contact(monkeypatch: pytest.MonkeyPatch, *, raises: Exception | None = None) -> list[dict[str, object]]:
    from verigence_security.services.service_contact_change import ContactChangeResult

    _caller(monkeypatch)
    app.dependency_overrides[platform_session] = lambda: _PasswordSession(None)
    _fake_clerk(monkeypatch, confirms=True)
    seen: list[dict[str, object]] = []

    class _Change:
        def __init__(self, _session: object) -> None:
            pass

        def change(self, **kwargs: object) -> ContactChangeResult:
            seen.append(kwargs)
            if raises is not None:
                raise raises
            return ContactChangeResult(USER, "new@example.test", None, True, False, True)

    monkeypatch.setattr(service_users, "ServiceContactChange", _Change)
    return seen


def test_allowed_integration_changes_the_email_of_a_login(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _contact(monkeypatch)
    response = client.post(
        f"/security/v1/service/users/{USER}/contact", json={"email": "new@example.test"}, headers=AUTH
    )
    assert response.status_code == 200
    assert response.json() == {
        "userId": USER,
        "email": "new@example.test",
        "mobile": None,
        "emailChanged": True,
        "mobileChanged": False,
        "oldEmailRemoved": True,
    }
    assert seen[0]["email"] == "new@example.test" and seen[0]["mobile"] is None


def test_contact_change_errors_are_told_apart(monkeypatch: pytest.MonkeyPatch) -> None:
    from verigence_security.adapters.clerk_backend import ClerkBackendError
    from verigence_security.services.service_contact_change import ContactConflict
    from verigence_security.services.v2_platform_user_create import InvalidUserInput

    cases: list[tuple[Exception, int]] = [
        (InvalidUserInput("bad"), 422),
        (LookupError("none"), 404),
        (ContactConflict("taken"), 409),
        (ValueError("no identity"), 409),
        (ClerkBackendError("x", status_code=422, provider_code="form_identifier_exists"), 409),
        (ClerkBackendError("x", status_code=503), 502),
    ]
    for error, expected in cases:
        _contact(monkeypatch, raises=error)
        response = client.post(
            f"/security/v1/service/users/{USER}/contact", json={"email": "a@example.test"}, headers=AUTH
        )
        assert response.status_code == expected, (error, response.text)


def test_contact_change_refuses_other_integrations(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _contact(monkeypatch)
    _caller(monkeypatch, subject="audit-core")
    app.dependency_overrides[platform_session] = lambda: _PasswordSession(None)
    response = client.post(
        f"/security/v1/service/users/{USER}/contact", json={"email": "a@example.test"}, headers=AUTH
    )
    assert response.status_code == 403 and seen == []
