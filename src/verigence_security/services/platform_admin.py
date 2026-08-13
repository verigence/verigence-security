from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from sqlalchemy.exc import IntegrityError

from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.core.types import AppEnvironment
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository

_PASSWORD_HASHER = PasswordHasher()
_ALLOWED_BOOTSTRAP_ENVS = {AppEnvironment.LOCAL, AppEnvironment.CI, AppEnvironment.DEV}


class PlatformAdminTokenService:
    TOKEN_TYPE = "PLATFORM_ADMIN"
    ROLE = "SUPER_ADMIN"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def issue(self, *, admin_id: str, username: str) -> tuple[str, datetime]:
        if not self.settings.security_private_key_pem or not self.settings.security_key_id:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        now = datetime.now(UTC)
        expires_at = now + timedelta(minutes=self.settings.platform_admin_token_ttl_minutes)
        payload: dict[str, Any] = {
            "iss": self.settings.security_token_issuer,
            "sub": admin_id,
            "aud": self.settings.platform_admin_token_audience,
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid4()),
            "token_type": self.TOKEN_TYPE,
            "admin_role": self.ROLE,
            "username": username,
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
            claims = jwt.decode(
                token,
                self.settings.security_public_key_pem,
                algorithms=["RS256"],
                issuer=self.settings.security_token_issuer,
                audience=self.settings.platform_admin_token_audience,
            )
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc
        if claims.get("token_type") != self.TOKEN_TYPE:
            raise security_error("AUTH_TOKEN_INVALID")
        if claims.get("admin_role") != self.ROLE:
            raise security_error("AUTH_TOKEN_INVALID")
        return claims


class PlatformAdminService:
    def __init__(self, repository: PlatformAdminRepository, settings: Settings) -> None:
        self.repository = repository
        self.settings = settings
        self.tokens = PlatformAdminTokenService(settings)

    def bootstrap(
        self,
        *,
        username: str,
        display_name: str,
        password: str,
        now: datetime,
    ) -> dict[str, Any]:
        if self.settings.app_env not in _ALLOWED_BOOTSTRAP_ENVS:
            raise ValueError("PLATFORM_ADMIN_BOOTSTRAP_NOT_ALLOWED")
        self.repository.lock_bootstrap()
        if self.repository.admin_count() != 0:
            self.repository.rollback()
            raise ValueError("PLATFORM_ADMIN_ALREADY_BOOTSTRAPPED")
        normalized_username = username.strip().lower()
        admin_id = str(uuid4())
        self.repository.create_admin(
            admin_id=admin_id,
            username=normalized_username,
            display_name=display_name.strip(),
            password_hash=_PASSWORD_HASHER.hash(password),
            now=now,
        )
        self.repository.commit()
        return {
            "admin_id": admin_id,
            "username": normalized_username,
            "display_name": display_name.strip(),
            "must_change_password": True,
        }

    def login(self, *, username: str, password: str, now: datetime) -> dict[str, Any]:
        normalized_username = username.strip().lower()
        admin = self.repository.admin_by_username(normalized_username)
        if admin is None or admin["status"] != "ACTIVE":
            raise security_error("AUTH_TOKEN_INVALID")
        try:
            valid = _PASSWORD_HASHER.verify(str(admin["password_hash"]), password)
        except (VerifyMismatchError, InvalidHashError) as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc
        if not valid:
            raise security_error("AUTH_TOKEN_INVALID")
        self.repository.mark_login(admin_id=str(admin["admin_id"]), now=now)
        self.repository.commit()
        token, expires_at = self.tokens.issue(
            admin_id=str(admin["admin_id"]),
            username=str(admin["username"]),
        )
        return {
            "access_token": token,
            "expires_at": expires_at,
            "admin_id": str(admin["admin_id"]),
            "username": str(admin["username"]),
            "role": PlatformAdminTokenService.ROLE,
            "must_change_password": bool(admin["must_change_password"]),
        }

    def create_tenant(
        self,
        *,
        tenant_code: str,
        tenant_name: str,
        now: datetime,
    ) -> dict[str, Any]:
        tenant_id = str(uuid4())
        try:
            self.repository.create_tenant(
                tenant_id=tenant_id,
                tenant_code=tenant_code.strip().lower(),
                tenant_name=tenant_name.strip(),
                now=now,
            )
            self.repository.commit()
        except IntegrityError as exc:
            self.repository.rollback()
            raise ValueError("TENANT_CODE_ALREADY_EXISTS") from exc
        return {
            "tenant_id": tenant_id,
            "tenant_code": tenant_code.strip().lower(),
            "tenant_name": tenant_name.strip(),
            "status": "CONFIGURING",
        }

    def list_tenants(self) -> list[dict[str, Any]]:
        return self.repository.tenants()
