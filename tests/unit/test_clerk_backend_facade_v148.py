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


def test_pending_user_uses_verified_placeholder_and_prepares_real_email() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []
    placeholder = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal placeholder
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        calls.append((request.method, str(request.url), body))
        if request.method == "POST" and request.url.path == "/v1/users":
            placeholder = str(body["email_address"][0])
            return httpx.Response(
                200,
                json={
                    "id": "user_pending",
                    "banned": True,
                    "primary_email_address_id": "idn_placeholder",
                    "email_addresses": [
                        {
                            "id": "idn_placeholder",
                            "email_address": placeholder,
                            "verification": {"status": "verified"},
                        }
                    ],
                },
            )
        if request.method == "POST" and request.url.path == "/v1/email_addresses":
            return httpx.Response(
                200,
                json={
                    "id": "idn_signup",
                    "email_address": "amit@example.com",
                    "verification": None,
                },
            )
        if request.method == "POST" and request.url.path.endswith("/prepare_verification"):
            return httpx.Response(
                200,
                json={"id": "ver_signup", "status": "unverified", "strategy": "email_code"},
            )
        if request.method == "GET" and request.url.path == "/v1/users/user_pending":
            return httpx.Response(
                200,
                json={
                    "id": "user_pending",
                    "banned": True,
                    "primary_email_address_id": "idn_placeholder",
                    "email_addresses": [
                        {
                            "id": "idn_placeholder",
                            "email_address": placeholder,
                            "verification": {"status": "verified"},
                        },
                        {
                            "id": "idn_signup",
                            "email_address": "amit@example.com",
                            "verification": None,
                        },
                    ],
                },
            )
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = ClerkBackendClient(_settings(), client=client).create_pending_email_user(
            first_name="Amit",
            last_name="Goyal",
            email="amit@example.com",
            password="safe-password-123",
        )
    finally:
        client.close()

    assert result == ("user_pending", "idn_signup", "ver_signup")
    assert placeholder.startswith("verigence-pending-")
    assert placeholder.endswith("@example.com")
    assert placeholder != "amit@example.com"
    assert calls[0][0:2] == ("POST", "https://api.clerk.test/v1/users")
    assert calls[0][2]["banned"] is True
    assert calls[0][2]["email_address"] == [placeholder]
    assert "email_address_identification_status" not in calls[0][2]
    assert calls[1] == (
        "POST",
        "https://api.clerk.test/v1/email_addresses",
        {
            "user_id": "user_pending",
            "email_address": "amit@example.com",
            "primary": False,
            "verified": False,
        },
    )
    assert calls[2] == (
        "POST",
        "https://api.clerk.test/v1/email_addresses/idn_signup/prepare_verification",
        {"strategy": "email_code"},
    )
    assert calls[3][0:2] == ("GET", "https://api.clerk.test/v1/users/user_pending")
    assert len(calls) == 4


def test_attempt_email_verification_sends_verification_id_and_user_code() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={"id": "ver_signup", "status": "verified", "strategy": "email_code"},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        verified = ClerkBackendClient(_settings(), client=client).attempt_email_verification(
            "idn_signup",
            "ver_signup",
            "123456",
        )
    finally:
        client.close()

    assert verified
    assert captured == {
        "url": "https://api.clerk.test/v1/email_addresses/idn_signup/attempt_verification",
        "payload": {"verification_id": "ver_signup", "code": "123456"},
    }


def test_finalize_pending_email_promotes_verified_signup_and_deletes_only_placeholder() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []
    reads = 0

    def user_payload(*, primary: str, include_placeholder: bool) -> dict[str, object]:
        addresses: list[dict[str, object]] = []
        if include_placeholder:
            addresses.append(
                {
                    "id": "idn_placeholder",
                    "email_address": "verigence-pending-abc@example.com",
                    "verification": {"status": "verified"},
                }
            )
        addresses.append(
            {
                "id": "idn_signup",
                "email_address": "amit@example.com",
                "verification": {"status": "verified", "strategy": "email_code"},
            }
        )
        return {
            "id": "user_pending",
            "banned": True,
            "primary_email_address_id": primary,
            "email_addresses": addresses,
        }

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reads
        body = json.loads(request.content.decode("utf-8")) if request.content else {}
        calls.append((request.method, str(request.url), body))
        if request.method == "GET" and request.url.path == "/v1/users/user_pending":
            reads += 1
            if reads == 1:
                return httpx.Response(200, json=user_payload(primary="idn_placeholder", include_placeholder=True))
            if reads == 2:
                return httpx.Response(200, json=user_payload(primary="idn_signup", include_placeholder=True))
            return httpx.Response(200, json=user_payload(primary="idn_signup", include_placeholder=False))
        if request.method == "PATCH" and request.url.path == "/v1/email_addresses/idn_signup":
            return httpx.Response(
                200,
                json={
                    "id": "idn_signup",
                    "email_address": "amit@example.com",
                    "verification": {"status": "verified"},
                },
            )
        if request.method == "DELETE" and request.url.path == "/v1/email_addresses/idn_placeholder":
            return httpx.Response(204)
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        ClerkBackendClient(_settings(), client=client).finalize_pending_email_user(
            clerk_user_id="user_pending",
            email_address_id="idn_signup",
            expected_email="amit@example.com",
        )
    finally:
        client.close()

    assert calls[1] == (
        "PATCH",
        "https://api.clerk.test/v1/email_addresses/idn_signup",
        {"primary": True, "verified": True},
    )
    assert calls[3][0:2] == (
        "DELETE",
        "https://api.clerk.test/v1/email_addresses/idn_placeholder",
    )
    assert reads == 3


@dataclass
class FakeClerk:
    user: ClerkBackendUser | None
    password_ok: bool = True
    totp_ok: bool = True
    fail: ClerkBackendError | None = None
    totp_calls: int = 0

    def find_user(self, identifier: str) -> ClerkBackendUser | None:
        _ = identifier
        if self.fail is not None:
            raise self.fail
        return self.user

    def get_user(self, clerk_user_id: str) -> dict[str, object]:
        _ = clerk_user_id
        if self.fail is not None:
            raise self.fail
        if self.user is None:
            raise ClerkBackendError("not found", status_code=404)
        return {
            "id": self.user.user_id,
            "first_name": "Amit",
            "last_name": "Goyal",
            "primary_email_address_id": "idn_active",
            "email_addresses": [
                {"id": "idn_active", "email_address": self.user.primary_email}
            ],
            "totp_enabled": self.user.totp_enabled,
            "banned": self.user.banned,
            "locked": self.user.locked,
        }

    def verify_password(self, *, clerk_user_id: str, password: str) -> bool:
        _ = clerk_user_id, password
        return self.password_ok

    def verify_totp(self, *, clerk_user_id: str, code: str) -> bool:
        _ = clerk_user_id, code
        self.totp_calls += 1
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


def test_backend_credential_service_accepts_active_user(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ClerkCredentialService(_settings(), clerk=FakeClerk(_user()))  # type: ignore[arg-type]
    monkeypatch.setattr(service, "_resolve_verigence_clerk_subject", lambda _email: "user_active")
    result = service.authenticate(identifier="amit@example.com", password="safe-password-123")
    assert result.clerk_user.user_id == "user_active"


def test_backend_credential_service_does_not_require_totp_in_phase1(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clerk = FakeClerk(_user(totp_enabled=True), totp_ok=False)
    service = ClerkCredentialService(_settings(), clerk=clerk)  # type: ignore[arg-type]
    monkeypatch.setattr(service, "_resolve_verigence_clerk_subject", lambda _email: "user_active")
    result = service.authenticate(identifier="amit@example.com", password="safe-password-123")

    assert result.clerk_user.user_id == "user_active"
    assert clerk.totp_calls == 0


@pytest.mark.parametrize("user", [_user(banned=True), _user(locked=True), None])
def test_backend_credential_service_fails_closed(
    user: ClerkBackendUser | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = ClerkCredentialService(_settings(), clerk=FakeClerk(user))  # type: ignore[arg-type]
    monkeypatch.setattr(service, "_resolve_verigence_clerk_subject", lambda _email: "user_active")
    with pytest.raises(SecurityError) as exc_info:
        service.authenticate(identifier="amit@example.com", password="wrong-or-inactive")
    assert exc_info.value.code == "AUTH_TOKEN_INVALID"


def test_backend_credential_service_maps_provider_outage(monkeypatch: pytest.MonkeyPatch) -> None:
    service = ClerkCredentialService(
        _settings(),
        clerk=FakeClerk(None, fail=ClerkBackendError("offline")),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(service, "_resolve_verigence_clerk_subject", lambda _email: "user_active")
    with pytest.raises(SecurityError) as exc_info:
        service.authenticate(identifier="amit@example.com", password="safe-password-123")
    assert exc_info.value.code == "IDENTITY_PROVIDER_UNAVAILABLE"
