from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt

from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.services.permissions import validate_permissions


@dataclass(frozen=True, slots=True)
class PlatformAdminClaims:
    user_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    must_change_password: bool


class PlatformAdminTokenService:
    AUDIENCE = "verigence-security-admin"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def issue(self, claims: PlatformAdminClaims) -> tuple[str, datetime]:
        if not self.settings.security_private_key_pem or not self.settings.security_key_id:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        ttl = self.settings.platform_admin_token_ttl_minutes
        if ttl is None:
            raise RuntimeError("PLATFORM_ADMIN_TOKEN_TTL_MINUTES is not configured")

        permissions = validate_permissions(list(claims.permissions))
        if not claims.roles or any(not role.startswith("platform.") for role in claims.roles):
            raise ValueError("Platform Admin token requires Platform roles")

        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=ttl)
        payload: dict[str, Any] = {
            "iss": self.settings.security_token_issuer,
            "sub": claims.user_id,
            "aud": self.AUDIENCE,
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid4()),
            "roles": list(claims.roles),
            "permissions": permissions,
            "must_change_password": claims.must_change_password,
        }
        try:
            token = jwt.encode(
                payload,
                self.settings.security_private_key_pem,
                algorithm="RS256",
                headers={"kid": self.settings.security_key_id},
            )
        except (ValueError, TypeError, jwt.PyJWTError) as exc:
            raise security_error("SIGNING_KEY_UNAVAILABLE") from exc
        return token, expires_at

    def verify(self, token: str) -> dict[str, Any]:
        if not self.settings.security_public_key_pem:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        try:
            payload = jwt.decode(
                token,
                self.settings.security_public_key_pem,
                algorithms=["RS256"],
                issuer=self.settings.security_token_issuer,
                audience=self.AUDIENCE,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "sub",
                        "jti",
                        "roles",
                        "permissions",
                        "must_change_password",
                    ]
                },
            )
            roles = [str(value) for value in payload.get("roles", [])]
            permissions = [str(value) for value in payload.get("permissions", [])]
            if not roles or any(not role.startswith("platform.") for role in roles):
                raise security_error("AUTH_TOKEN_INVALID")
            try:
                validate_permissions(permissions)
            except ValueError as exc:
                raise security_error("AUTH_TOKEN_INVALID") from exc
            if "tenant_id" in payload or "access_session_id" in payload:
                raise security_error("AUTH_TOKEN_INVALID")
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc
