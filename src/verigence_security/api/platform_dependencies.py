from __future__ import annotations

from collections.abc import Callable, Generator
from typing import Any

from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.db.session import build_session_factory
from verigence_security.services.platform_admin_token import PlatformAdminTokenService

platform_admin_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="PlatformAdminToken",
    bearerFormat="JWT",
    description="Security control-plane JWT with audience verigence-security-admin.",
)


def platform_session(
    settings: Settings = Depends(get_settings),
) -> Generator[Session, None, None]:
    factory = build_session_factory(settings)
    if factory is None:
        raise security_error("DATABASE_UNAVAILABLE")
    session = factory()
    try:
        yield session
    finally:
        session.close()


def platform_token(
    credentials: HTTPAuthorizationCredentials | None = Security(platform_admin_bearer),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise security_error("AUTH_TOKEN_INVALID")
    value = credentials.credentials.strip()
    if not value:
        raise security_error("AUTH_TOKEN_INVALID")
    return value


def platform_claims(
    token: str = Depends(platform_token),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    return PlatformAdminTokenService(settings).verify(token)


def require_platform_permission(permission_key: str) -> Callable[..., dict[str, Any]]:
    def dependency(claims: dict[str, Any] = Depends(platform_claims)) -> dict[str, Any]:
        if bool(claims.get("must_change_password")):
            raise security_error("PERMISSION_DENIED")
        permissions = {str(value) for value in claims.get("permissions", [])}
        if permission_key not in permissions:
            raise security_error("PERMISSION_DENIED")
        return claims

    return dependency
