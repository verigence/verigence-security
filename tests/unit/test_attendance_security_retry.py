import time
from uuid import uuid4

import httpx

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.security import SecurityAuthorizationClient


def test_authorization_retries_one_transient_503(monkeypatch) -> None:
    settings = AttendanceSettings(
        security_base_url="https://security.example",
        security_client_id="attendance",
        security_client_secret="secret",
        downstream_timeout_seconds=0.5,
    )
    calls: list[int] = []
    responses = [
        httpx.Response(503),
        httpx.Response(200, json={"allowed": True, "reasonCode": "ALLOWED"}),
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/security/v1/authorization/check"
        calls.append(1)
        return responses.pop(0)

    client = SecurityAuthorizationClient(settings, transport=httpx.MockTransport(handler))
    client._service_token = "cached-token"
    client._service_token_reuse_until = time.monotonic() + 600
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)

    payload = client.check(
        user_id=uuid4(),
        tenant_id=uuid4(),
        permission_key="attendance.self.read",
    )

    assert payload["allowed"] is True
    assert len(calls) == 2
    client.close()
