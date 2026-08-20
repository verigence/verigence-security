from __future__ import annotations

import pytest

from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError
from verigence_security.services import clerk_credentials
from verigence_security.services.clerk_credentials import ClerkCredentialService


class _Rows:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows

    def mappings(self) -> _Rows:
        return self

    def all(self) -> list[dict[str, object]]:
        return self._rows


class _Session:
    def __init__(self, rows: list[dict[str, object]]) -> None:
        self._rows = rows
        self.closed = False

    def execute(self, *_args: object, **_kwargs: object) -> _Rows:
        return _Rows(self._rows)

    def close(self) -> None:
        self.closed = True


class _NeverClerk:
    def get_user(self, _clerk_user_id: str) -> dict[str, object]:
        raise AssertionError("Pending approval login must not call Clerk")


def _settings() -> Settings:
    return Settings(
        clerk_secret_key="clerk-unit-test-credential",
        clerk_backend_api_url="https://api.clerk.test/v1",
    )


def test_pending_admin_approval_returns_explicit_lifecycle_denial_before_clerk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session(
        [
            {
                "provider_subject": "user_pending",
                "user_status": "PENDING",
                "principal_status": "ACTIVE",
                "identity_status": "ACTIVE",
                "pending_admin_approval": True,
            }
        ]
    )
    monkeypatch.setattr(
        clerk_credentials,
        "build_session_factory",
        lambda _settings: lambda: session,
    )
    service = ClerkCredentialService(_settings(), clerk=_NeverClerk())  # type: ignore[arg-type]

    with pytest.raises(SecurityError) as exc_info:
        service.authenticate(
            identifier="pending@example.com",
            password="not-used-for-pending-state",
        )

    assert exc_info.value.code == "USER_PENDING_APPROVAL"
    assert exc_info.value.status_code == 403
    assert session.closed
