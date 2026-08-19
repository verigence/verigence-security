from __future__ import annotations

from collections.abc import Generator
from uuid import UUID

from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.db.session import build_session_factory
from verigence_security.services.token_service import TokenService
from verigence_security.services.v2_human_actor import (
    HumanActorAuthenticationService,
    HumanActorContext,
)


security_human_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="SecurityHumanAccessToken",
    bearerFormat="JWT",
    description="Security-issued human access JWT.",
)


def security_human_user_id(
    credentials: HTTPAuthorizationCredentials | None = Security(security_human_bearer),
    settings: Settings = Depends(get_settings),
) -> str:
    """Validate the Security-issued human JWT and return its trusted global USER id."""

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise security_error("AUTH_TOKEN_INVALID")
    token = credentials.credentials.strip()
    if not token:
        raise security_error("AUTH_TOKEN_INVALID")
    claims = TokenService(settings).verify_human_token(token)
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise security_error("AUTH_TOKEN_INVALID")
    try:
        return str(UUID(subject))
    except ValueError as exc:
        raise security_error("AUTH_TOKEN_INVALID") from exc


def security_human_actor(
    user_id: str = Depends(security_human_user_id),
    settings: Settings = Depends(get_settings),
) -> Generator[HumanActorContext, None, None]:
    factory = build_session_factory(settings)
    if factory is None:
        raise security_error("DATABASE_UNAVAILABLE")
    session = factory()
    try:
        yield HumanActorAuthenticationService(session).authenticate_user_id(user_id)
    finally:
        session.close()


# Compatibility alias for existing route imports. It no longer validates or accepts Clerk JWTs.
clerk_human_actor = security_human_actor
