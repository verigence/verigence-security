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


def _verified_user() -> dict[str, object]:
    return {
        "id": "user_active",
        "primary_email_address_id": "idn_primary",
        "email_addresses": [
            {
                "id": "idn_primary",
                "email_address": "admin@example.com",
                "verification": {"status": "verified", "strategy": "email_code"},
            }
        ],
    }


def test_prepare_password_recovery_temporarily_unverifies_then_sends_code() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else {}
        calls.append((request.method, request.url.path, payload))
        if request.method == "GET" and request.url.path == "/v1/users/user_active":
            return httpx.Response(200, json=_verified_user())
        if request.method == "PATCH" and request.url.path == "/v1/email_addresses/idn_primary":
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
    assert calls == [
        ("GET", "/v1/users/user_active", {}),
        ("PATCH", "/v1/email_addresses/idn_primary", {"verified": False}),
        (
            "POST",
            "/v1/email_addresses/idn_primary/prepare_verification",
            {"strategy": "email_code"},
        ),
    ]


def test_prepare_password_recovery_restores_verified_state_when_prepare_fails() -> None:
    patches: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content.decode("utf-8")) if request.content else {}
        if request.method == "GET" and request.url.path == "/v1/users/user_active":
            return httpx.Response(200, json=_verified_user())
        if request.method == "PATCH" and request.url.path == "/v1/email_addresses/idn_primary":
            patches.append(payload)
            return httpx.Response(200, json={"id": "idn_primary"})
        if request.method == "POST" and request.url.path.endswith("/prepare_verification"):
            return httpx.Response(503, json={"errors": [{"code": "service_unavailable"}]})
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


def test_update_password_signs_out_other_sessions() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"id": "user_active"})

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
