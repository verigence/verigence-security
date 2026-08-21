from __future__ import annotations

import json

import httpx
import pytest

from verigence_security.adapters.clerk_backend import ClerkBackendClient
from verigence_security.config import Settings


def _settings() -> Settings:
    return Settings(
        clerk_secret_key="clerk-unit-test-credential",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )


def test_attempt_email_verification_reconciles_provider_verified_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads = 0
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reads, posts
        if request.method == "POST" and request.url.path.endswith("/attempt_verification"):
            posts += 1
            payload = json.loads(request.content.decode("utf-8"))
            assert payload == {"verification_id": "ver_signup", "code": "123456"}
            return httpx.Response(
                422,
                json={
                    "errors": [
                        {
                            "code": "verification_already_verified",
                            "message": "Verification is already complete",
                        }
                    ]
                },
            )
        if request.method == "GET" and request.url.path == "/v1/email_addresses/idn_signup":
            reads += 1
            status = "verified" if reads >= 2 else "unverified"
            return httpx.Response(
                200,
                json={
                    "id": "idn_signup",
                    "verification": {"status": status, "strategy": "email_code"},
                },
            )
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    monkeypatch.setattr("verigence_security.adapters.clerk_backend.sleep", lambda _seconds: None)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        verified = ClerkBackendClient(_settings(), client=client).attempt_email_verification(
            "idn_signup",
            "ver_signup",
            "123456",
        )
    finally:
        client.close()

    assert verified is True
    assert posts == 1
    assert reads == 2


def test_attempt_email_verification_does_not_retry_invalid_otp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads = 0
    posts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reads, posts
        if request.method == "POST" and request.url.path.endswith("/attempt_verification"):
            posts += 1
            return httpx.Response(
                422,
                json={"errors": [{"code": "verification_failed", "message": "Code is invalid"}]},
            )
        if request.method == "GET" and request.url.path == "/v1/email_addresses/idn_signup":
            reads += 1
            return httpx.Response(
                200,
                json={
                    "id": "idn_signup",
                    "verification": {"status": "unverified", "strategy": "email_code"},
                },
            )
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    monkeypatch.setattr("verigence_security.adapters.clerk_backend.sleep", lambda _seconds: None)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        verified = ClerkBackendClient(_settings(), client=client).attempt_email_verification(
            "idn_signup",
            "ver_signup",
            "654321",
        )
    finally:
        client.close()

    assert verified is False
    assert posts == 1
    assert reads == 4


def test_attempt_email_verification_reconciles_nonverified_success_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reads = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal reads
        if request.method == "POST" and request.url.path.endswith("/attempt_verification"):
            return httpx.Response(
                200,
                json={"id": "ver_signup", "status": "unverified", "strategy": "email_code"},
            )
        if request.method == "GET" and request.url.path == "/v1/email_addresses/idn_signup":
            reads += 1
            return httpx.Response(
                200,
                json={
                    "id": "idn_signup",
                    "verification": {"status": "verified", "strategy": "email_code"},
                },
            )
        raise AssertionError(f"Unexpected Clerk call: {request.method} {request.url}")

    monkeypatch.setattr("verigence_security.adapters.clerk_backend.sleep", lambda _seconds: None)
    client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        verified = ClerkBackendClient(_settings(), client=client).attempt_email_verification(
            "idn_signup",
            "ver_signup",
            "123456",
        )
    finally:
        client.close()

    assert verified is True
    assert reads == 1
