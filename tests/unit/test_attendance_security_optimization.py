import threading
import time
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import httpx
import pytest

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.security import (
    AttendanceAuthorizationError,
    SecurityAuthorizationClient,
)


def _settings() -> AttendanceSettings:
    return AttendanceSettings(
        security_base_url="https://security.example",
        security_client_id="attendance",
        security_client_secret="secret",
        downstream_timeout_seconds=0.5,
    )


def test_service_token_is_reused_across_different_permission_checks() -> None:
    token_calls = 0
    authorization_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal token_calls, authorization_calls
        if request.url.path == "/security/v1/service/token":
            token_calls += 1
            return httpx.Response(
                200,
                json={"accessToken": "shared-token", "expiresIn": 3600},
            )
        if request.url.path == "/security/v1/authorization/check":
            authorization_calls += 1
            return httpx.Response(200, json={"allowed": True, "reasonCode": "ALLOWED"})
        raise AssertionError(f"Unexpected request: {request.url}")

    client = SecurityAuthorizationClient(_settings(), transport=httpx.MockTransport(handler))
    user_id = uuid4()
    tenant_id = uuid4()

    client.check(user_id=user_id, tenant_id=tenant_id, permission_key="attendance.self.read")
    client.check(user_id=user_id, tenant_id=tenant_id, permission_key="attendance.self.write")

    assert token_calls == 1
    assert authorization_calls == 2
    client.close()


def test_identical_successful_allow_is_reused_for_page_burst() -> None:
    authorization_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal authorization_calls
        if request.url.path == "/security/v1/service/token":
            return httpx.Response(
                200,
                json={"accessToken": "shared-token", "expiresIn": 3600},
            )
        if request.url.path == "/security/v1/authorization/check":
            authorization_calls += 1
            return httpx.Response(200, json={"allowed": True, "reasonCode": "ALLOWED"})
        raise AssertionError(f"Unexpected request: {request.url}")

    client = SecurityAuthorizationClient(_settings(), transport=httpx.MockTransport(handler))
    user_id = uuid4()
    tenant_id = uuid4()

    first = client.check(
        user_id=user_id,
        tenant_id=tenant_id,
        permission_key="attendance.self.read",
    )
    second = client.check(
        user_id=user_id,
        tenant_id=tenant_id,
        permission_key="attendance.self.read",
    )

    assert first == second
    assert authorization_calls == 1
    client.close()


def test_denial_is_never_cached() -> None:
    authorization_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal authorization_calls
        if request.url.path == "/security/v1/service/token":
            return httpx.Response(
                200,
                json={"accessToken": "shared-token", "expiresIn": 3600},
            )
        if request.url.path == "/security/v1/authorization/check":
            authorization_calls += 1
            return httpx.Response(
                200,
                json={"allowed": False, "reasonCode": "PERMISSION_DENIED"},
            )
        raise AssertionError(f"Unexpected request: {request.url}")

    client = SecurityAuthorizationClient(_settings(), transport=httpx.MockTransport(handler))
    user_id = uuid4()
    tenant_id = uuid4()

    for _ in range(2):
        with pytest.raises(AttendanceAuthorizationError):
            client.check(
                user_id=user_id,
                tenant_id=tenant_id,
                permission_key="attendance.self.read",
            )

    assert authorization_calls == 2
    client.close()


def test_concurrent_identical_checks_coalesce_to_one_security_decision() -> None:
    authorization_calls = 0
    count_lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal authorization_calls
        if request.url.path == "/security/v1/service/token":
            return httpx.Response(
                200,
                json={"accessToken": "shared-token", "expiresIn": 3600},
            )
        if request.url.path == "/security/v1/authorization/check":
            with count_lock:
                authorization_calls += 1
            time.sleep(0.05)
            return httpx.Response(200, json={"allowed": True, "reasonCode": "ALLOWED"})
        raise AssertionError(f"Unexpected request: {request.url}")

    client = SecurityAuthorizationClient(_settings(), transport=httpx.MockTransport(handler))
    user_id = uuid4()
    tenant_id = uuid4()

    def check() -> dict[str, object]:
        return client.check(
            user_id=user_id,
            tenant_id=tenant_id,
            permission_key="attendance.self.read",
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(lambda _index: check(), range(4)))

    assert all(result["allowed"] is True for result in results)
    assert authorization_calls == 1
    client.close()
