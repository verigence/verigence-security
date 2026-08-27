from __future__ import annotations

from dataclasses import dataclass
from threading import Lock

from verigence_security.adapters.clerk_backend import (
    ClerkBackendClient,
    ClerkBackendError,
    ClerkBackendUser,
)
from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError, security_error


@dataclass(frozen=True, slots=True)
class ClerkCredentialResult:
    clerk_user: ClerkBackendUser


_shared_clerk_lock = Lock()
_shared_clerk_key: tuple[str, str] | None = None
_shared_clerk_client: ClerkBackendClient | None = None


def _shared_clerk(settings: Settings) -> ClerkBackendClient:
    """Reuse Clerk's outbound HTTP connection pool across credential logins.

    Credential values are never cached. Only the backend adapter/transport is reused so
    consecutive Clerk calls (find user, verify password, optional TOTP) can reuse TCP/TLS
    connections instead of constructing a new httpx client for every operation.
    """

    global _shared_clerk_key, _shared_clerk_client
    key = (
        settings.clerk_backend_api_url.rstrip('/'),
        settings.clerk_secret_key.strip(),
    )
    with _shared_clerk_lock:
        if _shared_clerk_client is None or _shared_clerk_key != key:
            _shared_clerk_client = ClerkBackendClient(settings)
            # Give the adapter one persistent client. ClerkBackendClient otherwise creates
            # and closes a temporary httpx.Client for each individual API operation.
            import httpx

            _shared_clerk_client._client = httpx.Client(timeout=10.0)  # noqa: SLF001
            _shared_clerk_key = key
        return _shared_clerk_client


class ClerkCredentialService:
    """Backend-only human credential verification against Clerk.

    Password/TOTP values are transient arguments. They are never persisted or returned. Clerk
    proves credential validity; Security remains responsible for all Verigence authorization.
    """

    def __init__(self, settings: Settings, clerk: ClerkBackendClient | None = None) -> None:
        self.clerk = clerk or _shared_clerk(settings)

    def authenticate(
        self,
        *,
        identifier: str,
        password: str,
        totp_code: str | None = None,
    ) -> ClerkCredentialResult:
        normalized = identifier.strip()
        if not normalized or not password:
            raise security_error("AUTH_TOKEN_INVALID")

        try:
            user = self.clerk.find_user(normalized)
            if user is None or user.banned or user.locked:
                raise security_error("AUTH_TOKEN_INVALID")
            if not self.clerk.verify_password(
                clerk_user_id=user.user_id,
                password=password,
            ):
                raise security_error("AUTH_TOKEN_INVALID")
            if user.totp_enabled and (
                not totp_code
                or not self.clerk.verify_totp(
                    clerk_user_id=user.user_id,
                    code=totp_code,
                )
            ):
                raise security_error("AUTH_TOKEN_INVALID")
            return ClerkCredentialResult(clerk_user=user)
        except SecurityError:
            raise
        except ClerkBackendError as exc:
            if exc.retryable:
                raise security_error("IDENTITY_PROVIDER_UNAVAILABLE") from exc
            # Do not expose identifier existence/provider details on authentication failures.
            raise security_error("AUTH_TOKEN_INVALID") from exc
