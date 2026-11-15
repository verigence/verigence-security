from __future__ import annotations

import secrets
from datetime import datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from verigence_security.api.dependencies import repository, token_service
from verigence_security.api.routes import app_sign_in
from verigence_security.config import Settings, get_settings
from verigence_security.main import app

client = TestClient(app, base_url="https://testserver")

USER_ID = "11111111-1111-1111-1111-111111111111"
SESSION_ID = "22222222-2222-2222-2222-222222222222"
DEVICE_ID = "33333333-3333-3333-3333-333333333333"
SEVASUTRA_DEVICE = "44444444-4444-4444-4444-444444444444"


class _FakeTokens:
    issued: list[Any] = []

    def verify_human_token(self, token: str) -> dict[str, object]:
        assert token == "verigence-app-access"
        return {"sub": USER_ID, "session_id": SESSION_ID, "device_id": DEVICE_ID}

    def verify_service_token(self, token: str, *, audience: str) -> dict[str, object]:
        assert audience == "security"
        return {"sub": {"sevasutra-service": "sevasutra", "other-service": "other"}[token]}

    def issue_human_token(self, claims: Any) -> str:
        self.__class__.issued.append(claims)
        return "sevasutra-access"


class _FakeCodes:
    rows: dict[str, dict[str, Any]] = {}

    def __init__(self, session: object) -> None:
        _ = session

    def create(self, **kw: Any) -> None:
        self.__class__.rows[kw["code_hash"]] = {**kw, "used": False}

    def take(self, *, code_hash: str, now: datetime) -> dict[str, Any] | None:
        row = self.__class__.rows.get(code_hash)
        if not row or row["used"] or row["expires_at"] <= now:
            return None
        row["used"] = True
        return {
            "user_id": row["user_id"],
            "client_key": row["client_key"],
            "redirect_uri": row["redirect_uri"],
            "code_challenge": row["code_challenge"],
        }

    def email_of(self, user_id: str) -> str | None:
        return "pc@jbr.test"


class _FakeActor:
    def __init__(self, session: object) -> None:
        _ = session

    def authenticate_user_id(self, user_id: str) -> object:
        assert user_id == USER_ID
        return SimpleNamespace(user_id=USER_ID, is_super_admin=False)


class _FakeObservation:
    status: str | None = "ACTIVE"

    def __init__(self, session: object) -> None:
        _ = session

    def session_status(self, **kw: object) -> str | None:
        return self.__class__.status


class _FakeIntegrations:
    def __init__(self, session: object) -> None:
        _ = session

    def active_service_integration(self, key: str) -> bool:
        return key in {"sevasutra", "other"}


@pytest.fixture(autouse=True)
def _deps(monkeypatch: pytest.MonkeyPatch):
    _FakeCodes.rows = {}
    _FakeTokens.issued = []
    _FakeObservation.status = "ACTIVE"
    app.dependency_overrides.clear()
    app.dependency_overrides[get_settings] = lambda: Settings(platform_admin_token_ttl_minutes=15)
    app.dependency_overrides[repository] = lambda: SimpleNamespace(s=object(), commit=lambda: None)
    app.dependency_overrides[token_service] = lambda: _FakeTokens()
    monkeypatch.setattr(app_sign_in, "AppSignInRepository", _FakeCodes)
    monkeypatch.setattr(app_sign_in, "HumanActorAuthenticationService", _FakeActor)
    monkeypatch.setattr(app_sign_in, "HumanObservationRepository", _FakeObservation)
    monkeypatch.setattr(app_sign_in, "V2AuthorizationRepository", _FakeIntegrations)
    monkeypatch.setattr(app_sign_in, "require_not_blocked", lambda *a, **k: None)
    monkeypatch.setattr(app_sign_in, "record_login_attempt", lambda *a, **k: None)
    yield
    app.dependency_overrides.clear()


def _code(verifier: str, redirect: str = "sevasutra://sso", client_key: str = "sevasutra") -> Any:
    return client.post(
        "/security/v1/auth/app-sign-in/code",
        headers={"Authorization": "Bearer verigence-app-access"},
        json={"client": client_key, "redirectUri": redirect, "codeChallenge": app_sign_in.pkce_challenge(verifier)},
    )


def _token(code: str, verifier: str, service: str = "sevasutra-service") -> Any:
    return client.post(
        "/security/v1/auth/app-sign-in/token",
        headers={"Authorization": f"Bearer {service}"},
        json={
            "code": code,
            "codeVerifier": verifier,
            "redirectUri": "sevasutra://sso",
            "device": {
                "deviceId": SEVASUTRA_DEVICE,
                "deviceType": "MOBILE",
                "platform": "ANDROID",
                "browserName": "SevaSutra",
            },
        },
    )


def test_code_then_token_signs_the_person_in_to_the_app_once() -> None:
    verifier = secrets.token_urlsafe(48)
    made = _code(verifier)
    assert made.status_code == 200
    assert made.json()["clientName"] == "SevaSutra"
    stored = next(iter(_FakeCodes.rows.values()))
    assert stored["code_hash"] != made.json()["code"]
    got = _token(made.json()["code"], verifier)
    assert got.status_code == 200
    assert got.json()["accessToken"] == "sevasutra-access"
    assert got.json()["email"] == "pc@jbr.test"
    claims = _FakeTokens.issued[-1]
    assert claims.user_id == USER_ID and claims.device_id == SEVASUTRA_DEVICE and claims.session_id != SESSION_ID
    # Used once.
    assert _token(made.json()["code"], verifier).status_code == 401


def test_wrong_verifier_other_service_or_unknown_redirect_get_nothing() -> None:
    verifier = secrets.token_urlsafe(48)
    assert _code(verifier, redirect="https://evil.example/cb").status_code == 401
    assert _code(verifier, client_key="unknown").status_code == 401
    code = _code(verifier).json()["code"]
    assert _token(code, secrets.token_urlsafe(48)).status_code == 401
    code = _code(verifier).json()["code"]
    assert _token(code, verifier, service="other-service").status_code == 401


def test_a_superseded_verigence_session_gets_no_code() -> None:
    _FakeObservation.status = "SUPERSEDED"
    assert _code(secrets.token_urlsafe(48)).status_code == 401
