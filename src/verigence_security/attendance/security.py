from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any
from uuid import UUID

import httpx
import jwt

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.schemas import AttendanceRosterMember


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


class SecurityAuthorizationClient:
    """Small cached client for Security v2 authorization and Attendance-only roster reads.

    The Attendance process owns this cache. It never adds work to the Security login
    path and every downstream call has a short bounded timeout.
    """

    def __init__(self, settings: AttendanceSettings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._service_token: str | None = None
        self._service_token_expires_at = 0.0

    def _token(self) -> str:
        now = time.monotonic()
        if self._service_token and now < self._service_token_expires_at - 30:
            return self._service_token
        with self._lock:
            now = time.monotonic()
            if self._service_token and now < self._service_token_expires_at - 30:
                return self._service_token
            if not (
                self.settings.security_base_url.strip()
                and self.settings.security_client_id.strip()
                and self.settings.security_client_secret
            ):
                raise AttendanceDependencyError("Attendance Security client is not configured")
            try:
                response = httpx.post(
                    f"{self.settings.security_base_url.rstrip('/')}/security/v1/service/token",
                    data={"audience": "security"},
                    auth=(self.settings.security_client_id, self.settings.security_client_secret),
                    timeout=self.settings.downstream_timeout_seconds,
                )
                response.raise_for_status()
                payload = response.json()
                token = str(payload["accessToken"])
                expires_in = max(60, int(payload.get("expiresIn", 300)))
            except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
                raise AttendanceDependencyError("Security service token unavailable") from exc
            self._service_token = token
            self._service_token_expires_at = now + expires_in
            return token

    def check(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID,
        permission_key: str,
    ) -> dict[str, Any]:
        if not self.settings.security_base_url.strip():
            raise AttendanceDependencyError("Attendance Security base URL is not configured")
        try:
            response = httpx.post(
                f"{self.settings.security_base_url.rstrip('/')}/security/v1/authorization/check",
                headers={"Authorization": f"Bearer {self._token()}"},
                json={
                    "userId": str(user_id),
                    "tenantId": str(tenant_id),
                    "permissionKey": permission_key,
                },
                timeout=self.settings.downstream_timeout_seconds,
            )
            response.raise_for_status()
            raw_payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise AttendanceDependencyError("Security authorization is temporarily unavailable") from exc
        if not isinstance(raw_payload, dict):
            raise AttendanceDependencyError("Security authorization response is invalid")
        payload: dict[str, Any] = {str(key): value for key, value in raw_payload.items()}
        if not bool(payload.get("allowed")):
            raise AttendanceAuthorizationError(str(payload.get("reasonCode", "PERMISSION_DENIED")))
        return payload

    def active_roster(self, *, tenant_id: UUID) -> list[AttendanceRosterMember]:
        if not self.settings.security_base_url.strip():
            raise AttendanceDependencyError("Attendance Security base URL is not configured")
        base = self.settings.security_base_url.rstrip("/")
        roster_url = f"{base}/security/v1/internal/attendance/tenants/{tenant_id}/roster"
        try:
            response = httpx.get(
                roster_url,
                headers={"Authorization": f"Bearer {self._token()}"},
                timeout=self.settings.downstream_timeout_seconds,
            )
            response.raise_for_status()
            payload = response.json()
            items = payload.get("items") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                raise ValueError("Roster payload does not contain items")
            return [AttendanceRosterMember.model_validate(item) for item in items]
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise AttendanceDependencyError("Security attendance roster is temporarily unavailable") from exc

    def allowed(
        self,
        *,
        user_id: UUID,
        tenant_id: UUID,
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
