from __future__ import annotations

import json

import httpx

from verigence_security.adapters.clerk_backend import ClerkBackendClient
from verigence_security.config import Settings


def _settings() -> Settings:
    return Settings(
        clerk_secret_key="clerk-unit-test-credential",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )


def test_verified_email_requires_matching_clerk_verification_state() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "https://api.clerk.test/v1/users/user_verified"
        return httpx.Response(
            200,
            json={
                "id": "user_verified",
                "email_addresses": [
                    {
                        "id": "idn_1",
                        "email_address": "Amit@Example.com",
                        "verification": {"status": "verified", "strategy": "email_code"},
                    }
                ],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        clerk = ClerkBackendClient(_settings(), client=client)
        assert clerk.is_email_verified("user_verified", "amit@example.com")
        assert not clerk.is_email_verified("user_verified", "other@example.com")
    finally:
        client.close()


def test_unverified_email_is_rejected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "user_unverified",
                "email_addresses": [
                    {
                        "id": "idn_2",
                        "email_address": "amit@example.com",
                        "verification": {"status": "unverified", "strategy": "email_code"},
                    }
                ],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        assert not ClerkBackendClient(_settings(), client=client).is_email_verified(
            "user_unverified",
            "amit@example.com",
        )
    finally:
        client.close()


def test_profile_sync_updates_names_only() -> None:
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["payload"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"id": "user_verified"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        ClerkBackendClient(_settings(), client=client).update_user_profile(
            "user_verified",
            first_name="Amit",
            last_name="Goyal",
        )
    finally:
        client.close()

    assert captured == {
        "method": "PATCH",
        "url": "https://api.clerk.test/v1/users/user_verified",
        "payload": {"first_name": "Amit", "last_name": "Goyal"},
    }
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert "email_address" not in payload
    assert "phone_number" not in payload
    assert "password" not in payload
