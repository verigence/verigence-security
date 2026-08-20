from __future__ import annotations

import json

import httpx
import pytest

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.adapters.clerk_password_recovery import (
    prepare_password_recovery_email,
    update_password,
)
from verigence_security.config import Settings


def _settings() -> Settings:
    return Settings(
        clerk_secret_key="clerk-unit-test-credential",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )


def _verified_user(*, include_placeholder: bool = False) -> dict[str, object]:
    emails: list[dict[str, object]] = [
        {
            "id": "idn_primary",
            "email_address": "admin@example.com",
            "verification": {"status": "verified", "strategy": "email_code"},
        }
    ]
    if include_placeholder:
        emails.append(
            {
                "id": "idn_recovery",
                "email_address": "verigence-recovery-test@example.com",
                "verification": {"status": "verified"},
            }
        )
    return {
        "id": "user_active",
        "primary_email_address_id": "idn_primary",
        "email_addresses": emails,
    }


def test_prepare_password_recovery_keeps_verified_placeholder_before_unverifying_registered_email() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []
    placeholder_created = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal placeholder_created
        payload = json.loads(request.content.decode("utf-8")) if request.content else {}
        calls.append((request.method, request.url.path, payload))
        if request.method == "GET" and request.url.path == "/v1/users/user_active":
            return httpx.Response(200, json=_verified_user())
        if request.method == "POST" and request.url.path == "/v1/email_addresses":
            assert payload["user_id"] == "user_active"
            assert payload["primary"] is False
            assert payload["verified"] is True
            assert str(payload["email_address"]).startswith("verigence-recovery-")
            placeholder_created = True
            return httpx.Response(
                200,
                json={
                    "id": "idn_recovery",
                    "email_address": payload["email_address"],
                    "verification": {"status": "verified"},
                },
            )
        if request.method == "PATCH" and request.url.path == "/v1/email_addresses/idn_primary":
            # This models the production Clerk invariant: the registered email may only become
            # unverified after Security has attached another verified address.
            assert placeholder_created is True
            assert payload == {"verified": False}
            return httpx.Response(
                200,
                json={
                    "id": "idn_primary",
                    "email_address": "admin@example.com",
                    "verification": {"status": "unverified"},
                },
            )
        if request.method == "POST" and request.url.path.endswith("/prepare_verification"):
            return httpx.Response(
                200,
                json={"id": "ver_reset", "status": "unverified", "strategy": "email_code"},
            )
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        clerk = ClerkBackendClient(_settings(), client=client)
        result = prepare_password_recovery_email(
            clerk,
            clerk_user_id="user_active",
            expected_email="admin@example.com",
        )
    finally:
        client.close()

    assert result == ("idn_primary", "ver_reset")
    assert [path for method, path, _ in calls if method == "POST"] == [
        "/v1/email_addresses",
        "/v1/email_addresses/idn_primary/prepare_verification",
    ]


def test_prepare_password_recovery_restores_email_and_removes_placeholder_when_prepare_fails() -> None:
    patches: list[dict[str, object]] = []
    deleted: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else {}
        if request.method == "GET" and request.url.path == "/v1/users/user_active":
            return httpx.Response(200, json=_verified_user())
        if request.method == "POST" and request.url.path == "/v1/email_addresses":
            return httpx.Response(
                200,
                json={
                    "id": "idn_recovery",
                    "email_address": payload["email_address"],
                    "verification": {"status": "verified"},
                },
            )
        if request.method == "PATCH" and request.url.path == "/v1/email_addresses/idn_primary":
            patches.append(payload)
            return httpx.Response(
                200,
                json={
                    "id": "idn_primary",
                    "email_address": "admin@example.com",
                    "verification": {"status": "verified" if payload.get("verified") else "unverified"},
                },
            )
        if request.method == "POST" and request.url.path.endswith("/prepare_verification"):
            return httpx.Response(503, json={"errors": [{"code": "service_unavailable"}]})
        if request.method == "DELETE" and request.url.path == "/v1/email_addresses/idn_recovery":
            deleted.append(request.url.path)
            return httpx.Response(200, json={"deleted": True})
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        clerk = ClerkBackendClient(_settings(), client=client)
        with pytest.raises(ClerkBackendError):
            prepare_password_recovery_email(
                clerk,
                clerk_user_id="user_active",
                expected_email="admin@example.com",
            )
    finally:
        client.close()

    assert patches == [{"verified": False}, {"verified": True}]
    assert deleted == ["/v1/email_addresses/idn_recovery"]


def test_update_password_signs_out_other_sessions() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "PATCH" and request.url.path == "/v1/users/user_active":
            captured["method"] = request.method
            captured["path"] = request.url.path
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json={"id": "user_active"})
        if request.method == "GET" and request.url.path == "/v1/users/user_active":
            return httpx.Response(200, json=_verified_user())
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        update_password(
            ClerkBackendClient(_settings(), client=client),
            clerk_user_id="user_active",
            password="strong-password-123",
        )
    finally:
        client.close()

    assert captured == {
        "method": "PATCH",
        "path": "/v1/users/user_active",
        "payload": {
            "password": "strong-password-123",
            "sign_out_of_other_sessions": True,
        },
    }
