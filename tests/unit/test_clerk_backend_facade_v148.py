from __future__ import annotations

import json
from dataclasses import dataclass

import httpx
import pytest

from verigence_security.adapters.clerk_backend import (
    ClerkBackendClient,
    ClerkBackendError,
    ClerkBackendUser,
)
from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError
from verigence_security.services.clerk_credentials import ClerkCredentialService


def _settings() -> Settings:
    return Settings(
        clerk_secret_key="clerk-unit-test-credential",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )


def test_pending_user_is_banned_unverified_then_email_code_is_prepared() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        calls.append((request.method, str(request.url), body))
        if request.method == "POST" and request.url.path == "/v1/users":
            return httpx.Response(
                200,
                json={
                    "id": "user_pending",
                    "banned": True,
                    "primary_email_address_id": "idn_signup",
                    "email_addresses": [
                        {"id": "idn_signup", "email_address": "amit@example.com"}
                    ],
                },
            )
        if request.method == "PATCH":
            return httpx.Response(
                200,
                json={
                    "id": "idn_signup",
                    "email_address": "amit@example.com",
                    "verification": {"status": "unverified"},
                },
            )
        return httpx.Response(
            200,
            json={
                "id": "idn_signup",
                "email_address": "amit@example.com",
                "verification": {"status": "unverified", "strategy": "email_code"},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        user_id, email_id = ClerkBackendClient(_settings(), client=client).create_pending_email_user(
            first_name="Amit",
            last_name="Goyal",
            email="amit@example.com",
            password="safe-password-123",
        )
    finally:
        client.close()

    assert (user_id, email_id) == ("user_pending", "idn_signup")
    assert calls[0][0:2] == ("POST", "https://api.clerk.test/v1/users")
    assert calls[0][2]["banned"] is True
    assert calls[0][2]["email_address"] == ["amit@example.com"]
    assert calls[1] == (
        "PATCH",
        "https://api.clerk.test/v1/email_addresses/idn_signup",
        {"verified": False},
    )
    assert calls[2] == (
        "POST",
        "https://api.clerk.test/v1/email_addresses/idn_signup/prepare_verification",
        {"strategy": "email_code"},
    )


def test_attempt_email_verification_uses_user_supplied_code() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={
                "id": "idn_signup",
                "email_address": "amit@example.com",
                "verification": {"status": "verified", "strategy": "email_code"},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        verified = ClerkBackendClient(_settings(), client=client).attempt_email_verification(
            "idn_signup",
            "123456",
        )
    finally:
        client.close()

    assert verified
    assert captured == {
        "url": "https://api.clerk.test/v1/email_addresses/idn_signup/attempt_verification",
        "payload": {"code": "123456"},
    }


@dataclass
class FakeClerk:
    user: ClerkBackendUser | None
    password_ok: bool = True
    totp_ok: bool = True
    fail: ClerkBackendError | None = None

    def find_user(self, identifier: str) -> ClerkBackendUser | None:
        _ = identifier
        if self.fail is not None:
            raise self.fail
        return self.user

    def verify_password(self, *, clerk_user_id: str, password: str) -> bool:
        _ = clerk_user_id, password
        return self.password_ok

    def verify_totp(self, *, clerk_user_id: str, code: str) -> bool:
        _ = clerk_user_id, code
        return self.totp_ok


def _user(*, banned: bool = False, locked: bool = False, totp_enabled: bool = False) -> ClerkBackendUser:
    return ClerkBackendUser(
        user_id="user_active",
        display_name="Amit Goyal",
        primary_email="amit@example.com",
        totp_enabled=totp_enabled,
        banned=banned,
        locked=locked,
    )


def test_backend_credential_service_accepts_active_user() -> None:
    result = ClerkCredentialService(
        _settings(),
        clerk=FakeClerk(_user()),  # type: ignore[arg-type]
    ).authenticate(identifier="amit@example.com", password="safe-password-123")
    assert result.clerk_user.user_id == "user_active"


@pytest.mark.parametrize("user", [_user(banned=True), _user(locked=True), None])
def test_backend_credential_service_fails_closed(user: ClerkBackendUser | None) -> None:
    with pytest.raises(SecurityError) as exc_info:
        ClerkCredentialService(
            _settings(),
            clerk=FakeClerk(user),  # type: ignore[arg-type]
        ).authenticate(identifier="amit@example.com", password="wrong-or-inactive")
    assert exc_info.value.code == "AUTH_TOKEN_INVALID"


def test_backend_credential_service_maps_provider_outage() -> None:
    with pytest.raises(SecurityError) as exc_info:
        ClerkCredentialService(
            _settings(),
            clerk=FakeClerk(None, fail=ClerkBackendError("offline")),  # type: ignore[arg-type]
        ).authenticate(identifier="amit@example.com", password="safe-password-123")
    assert exc_info.value.code == "IDENTITY_PROVIDER_UNAVAILABLE"
