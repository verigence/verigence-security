from __future__ import annotations

import json

import httpx

from verigence_security.adapters.clerk_backend import ClerkBackendClient
from verigence_security.config import Settings


def test_create_user_sends_email_name_password_but_no_phone_or_username() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["authorization"] = request.headers.get("Authorization")
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"id": "user_phase1_test"})

    settings = Settings(
        clerk_secret_key="sk_test_not_a_real_secret",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result = ClerkBackendClient(settings, client=client).create_user(
            first_name="Amit",
            last_name="Goyal",
            email="amit@example.com",
            password="safe-password-123",
        )
    finally:
        client.close()

    assert result == "user_phase1_test"
    assert captured["method"] == "POST"
    assert captured["url"] == "https://api.clerk.test/v1/users"
    assert captured["authorization"] == "Bearer sk_test_not_a_real_secret"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload == {
        "first_name": "Amit",
        "last_name": "Goyal",
        "email_address": ["amit@example.com"],
        "password": "safe-password-123",
    }
    assert "phone_number" not in payload
    assert "username" not in payload


def test_delete_user_uses_backend_compensation_endpoint() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"id": "user_phase1_test"})

    settings = Settings(
        clerk_secret_key="sk_test_not_a_real_secret",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        ClerkBackendClient(settings, client=client).delete_user("user_phase1_test")
    finally:
        client.close()

    assert captured == {
        "method": "DELETE",
        "url": "https://api.clerk.test/v1/users/user_phase1_test",
    }
