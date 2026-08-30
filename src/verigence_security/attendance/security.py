from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
import jwt

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.schemas import AttendanceRosterMember

_RETRYABLE_SECURITY_STATUSES = {502, 503, 504}
_SECURITY_RETRY_DELAY_SECONDS = 0.15

# Align Attendance with the lightweight Security runtime pattern already proven in
# Audit Core. Backend ServiceIntegration credentials are reused server-side until
# shortly before expiry. Human JWT validation still occurs on every Attendance API
# request, and browser state is never an authorization cache.
_SERVICE_TOKEN_EXPIRY_SAFETY_SECONDS = 300.0
_SERVICE_TOKEN_FALLBACK_REUSE_SECONDS = 60.0

# One Attendance page opens several lazy requests together (Today, Policy, History
# and sometimes Overview). Reuse only a successful identical Security ALLOW briefly
# to coalesce that single page burst. DENY and dependency errors are never cached.
_AUTHORIZATION_ALLOW_REUSE_SECONDS = 10.0


class AttendanceAuthenticationError(RuntimeError):
    pass


class AttendanceAuthorizationError(RuntimeError):
    pass


class AttendanceDependencyError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VerifiedHuman:
    user_id: UUID


def verify_human_token(token: str, settings: AttendanceSettings) -> VerifiedHuman:
    if not settings.security_public_key_pem.strip():
        raise AttendanceDependencyError("Attendance Security public key is not configured")
    try:
        payload = jwt.decode(
            token,
            settings.security_public_key_pem,
            algorithms=["RS256"],
            issuer=settings.security_token_issuer,
            audience=settings.security_token_audience,
            options={"require": ["exp", "iat", "sub", "actor_type"]},
        )
    except jwt.PyJWTError as exc:
        raise AttendanceAuthenticationError("Invalid or expired Security token") from exc
    if payload.get("actor_type") != "USER":
        raise AttendanceAuthenticationError("Attendance requires a human USER token")
    try:
        return VerifiedHuman(user_id=UUID(str(payload["sub"])))
    except (KeyError, ValueError, TypeError) as exc:
        raise AttendanceAuthenticationError("Security token subject is invalid") from exc


def _retryable_security_error(exc: httpx.HTTPError) -> bool:
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code in _RETRYABLE_SECURITY_STATUSES
    return isinstance(exc, httpx.RequestError)


def _service_token_reuse_seconds(expires_in: object) -> float:
    if expires_in is None:
        return _SERVICE_TOKEN_FALLBACK_REUSE_SECONDS
    if isinstance(expires_in, bool) or not isinstance(expires_in, int) or expires_in <= 0:
        raise ValueError("Security service-token response has invalid expiresIn")
    return max(1.0, float(expires_in) - _SERVICE_TOKEN_EXPIRY_SAFETY_SECONDS)


class SecurityAuthorizationClient:
    """Shared Security v2 client for Attendance authorization and roster reads.

    The Attendance process reuses one HTTP connection pool and one backend
    ServiceIntegration token while valid. Successful identical ALLOW decisions may be
    reused for a few seconds to collapse a lazy page burst. Human JWT verification is
    still performed independently on every protected Attendance request.
    """

    def __init__(
        self,
        settings: AttendanceSettings,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self._base_url = settings.security_base_url.rstrip("/")
        self._client = httpx.Client(
            base_url=self._base_url or "https://security.invalid",
            timeout=settings.downstream_timeout_seconds,
            transport=transport,
        )
        self._service_token_lock = threading.Lock()
        self._service_token: str | None = None
        self._service_token_reuse_until = 0.0
        self._allow_cache: dict[tuple[str, str, str], tuple[float, dict[str, Any]]] = {}
        self._allow_cache_lock = threading.Lock()
        self._decision_locks: dict[tuple[str, str, str], threading.Lock] = {}
        self._decision_locks_lock = threading.Lock()

    def close(self) -> None:
        self._client.close()

    def _call_with_retry(self, request: Callable[[], httpx.Response]) -> httpx.Response:
        """Retry one transient Security transport/502/503/504 failure."""
        last_error: httpx.HTTPError | None = None
        for attempt in range(2):
            try:
                response = request()
                response.raise_for_status()
                return response
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt == 0 and _retryable_security_error(exc):
                    time.sleep(_SECURITY_RETRY_DELAY_SECONDS)
                    continue
                raise
        assert last_error is not None
        raise last_error

    def warm_service_token(self) -> None:
        """Allow deployment/runtime probes to warm the backend token without user data."""
        self._token()

    def _invalidate_service_token(self, token: str) -> None:
        with self._service_token_lock:
            if self._service_token == token:
                self._service_token = None
                self._service_token_reuse_until = 0.0

    def _token(self) -> str:
        now = time.monotonic()
        if self._service_token and now < self._service_token_reuse_until:
            return self._service_token
        with self._service_token_lock:
            now = time.monotonic()
            if self._service_token and now < self._service_token_reuse_until:
                return self._service_token
            if not (
                self._base_url
                and self.settings.security_client_id.strip()
                and self.settings.security_client_secret
            ):
                raise AttendanceDependencyError("Attendance Security client is not configured")
            try:
                response = self._call_with_retry(
                    lambda: self._client.post(
                        "/security/v1/service/token",
                        data={"audience": "security"},
                        auth=(
                            self.settings.security_client_id,
                            self.settings.security_client_secret,
                        ),
                    )
                )
                payload = response.json()
                token = str(payload["accessToken"])
                if not token:
                    raise ValueError("Security service-token response has no accessToken")
                reuse_seconds = _service_token_reuse_seconds(payload.get("expiresIn"))
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
                raise AttendanceDependencyError("Security service token unavailable") from exc
            self._service_token = token
            self._service_token_reuse_until = now + reuse_seconds
            return token

    def _authorization_key(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID | None,
        permission_key: str,
    ) -> tuple[str, str, str]:
        return (
            str(user_id),
            str(tenant_id) if tenant_id is not None else "<GLOBAL>",
            permission_key,
        )

    def _cached_allow(self, key: tuple[str, str, str]) -> dict[str, Any] | None:
        now = time.monotonic()
        with self._allow_cache_lock:
            cached = self._allow_cache.get(key)
            if cached is None:
                return None
            expires_at, payload = cached
            if expires_at <= now:
                self._allow_cache.pop(key, None)
                return None
            return dict(payload)

    def _remember_allow(self, key: tuple[str, str, str], payload: dict[str, Any]) -> None:
        if payload.get("allowed") is not True:
            return
        with self._allow_cache_lock:
            self._allow_cache[key] = (
                time.monotonic() + _AUTHORIZATION_ALLOW_REUSE_SECONDS,
                dict(payload),
            )

    def _decision_lock(self, key: tuple[str, str, str]) -> threading.Lock:
        with self._decision_locks_lock:
            lock = self._decision_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._decision_locks[key] = lock
            return lock

    def _request_authorization(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID | None,
        permission_key: str,
    ) -> dict[str, Any]:
        for token_attempt in range(2):
            token = self._token()
            try:
                response = self._call_with_retry(
                    lambda token=token: self._client.post(
                        "/security/v1/authorization/check",
                        headers={"Authorization": f"Bearer {token}"},
                        json={
                            "userId": str(user_id),
                            "tenantId": str(tenant_id) if tenant_id is not None else None,
                            "permissionKey": permission_key,
                        },
                    )
                )
                raw_payload = response.json()
                break
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 401 and token_attempt == 0:
                    self._invalidate_service_token(token)
                    continue
                raise AttendanceDependencyError(
                    "Security authorization is temporarily unavailable"
                ) from exc
            except (httpx.HTTPError, ValueError) as exc:
                raise AttendanceDependencyError(
                    "Security authorization is temporarily unavailable"
                ) from exc
        else:  # pragma: no cover - loop always returns/raises
            raise AttendanceDependencyError("Security authorization is temporarily unavailable")

        if not isinstance(raw_payload, dict):
            raise AttendanceDependencyError("Security authorization response is invalid")
        payload: dict[str, Any] = {str(key): value for key, value in raw_payload.items()}
        if not bool(payload.get("allowed")):
            raise AttendanceAuthorizationError(str(payload.get("reasonCode", "PERMISSION_DENIED")))
        return payload

    def check(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID | None,
        permission_key: str,
    ) -> dict[str, Any]:
        if not self._base_url:
            raise AttendanceDependencyError("Attendance Security base URL is not configured")
        key = self._authorization_key(
            user_id=user_id,
            tenant_id=tenant_id,
            permission_key=permission_key,
        )
        cached = self._cached_allow(key)
        if cached is not None:
            return cached

        # Today/Policy/History may arrive concurrently for the exact same user,
        # Tenant and permission. Only the first request performs the live Security
        # decision; followers reuse that successful ALLOW for the short burst window.
        with self._decision_lock(key):
            cached = self._cached_allow(key)
            if cached is not None:
                return cached
            payload = self._request_authorization(
                user_id=user_id,
                tenant_id=tenant_id,
                permission_key=permission_key,
            )
            self._remember_allow(key, payload)
            return payload

    def active_roster(self, *, tenant_id: UUID) -> list[AttendanceRosterMember]:
        if not self._base_url:
            raise AttendanceDependencyError("Attendance Security base URL is not configured")
        for token_attempt in range(2):
            token = self._token()
            try:
                response = self._call_with_retry(
                    lambda token=token: self._client.get(
                        f"/security/v1/internal/attendance/tenants/{tenant_id}/roster",
                        headers={"Authorization": f"Bearer {token}"},
                    )
                )
                payload = response.json()
                items = payload.get("items") if isinstance(payload, dict) else None
                if not isinstance(items, list):
                    raise ValueError("Roster payload does not contain items")
                return [AttendanceRosterMember.model_validate(item) for item in items]
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 401 and token_attempt == 0:
                    self._invalidate_service_token(token)
                    continue
                raise AttendanceDependencyError(
                    "Security attendance roster is temporarily unavailable"
                ) from exc
            except (httpx.HTTPError, ValueError, TypeError) as exc:
                raise AttendanceDependencyError(
                    "Security attendance roster is temporarily unavailable"
                ) from exc
        raise AttendanceDependencyError("Security attendance roster is temporarily unavailable")

    def allowed(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID | None,
        permission_key: str,
    ) -> tuple[bool, dict[str, Any] | None]:
        try:
            payload = self.check(
                user_id=user_id,
                tenant_id=tenant_id,
                permission_key=permission_key,
            )
            return True, payload
        except AttendanceAuthorizationError:
            return False, None
