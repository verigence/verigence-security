from __future__ import annotations

from collections.abc import Generator

import jwt
from fastapi import Depends, Header, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from verigence_security.adapters.identity import (
    AuthenticatedIdentity,
    ClerkJwtIdentityProvider,
    DevMockIdentityProvider,
)
from verigence_security.adapters.network_risk import (
    MockNetworkRiskAdapter,
    NetworkRiskAdapter,
    UnknownNetworkRiskAdapter,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.correlation import CORRELATION_ID_PATTERN, HEADER
from verigence_security.core.errors import security_error
from verigence_security.core.types import AppEnvironment
from verigence_security.db.session import build_session_factory
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.token_service import TokenService




def correlation_header_parameter(
    value: str | None = Header(
        default=None,
        alias=HEADER,
        min_length=1,
        max_length=128,
        pattern=CORRELATION_ID_PATTERN,
    ),
) -> str | None:
    """OpenAPI declaration for the middleware-owned correlation header contract."""

    return value

user_identity_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="UserIdentityToken",
    bearerFormat="JWT",
    description=(
        "Clerk session JWT in UAT/Production or DEV mock identity JWT "
        "in permitted DEV mode."
    ),
)


def bearer_token(
    credentials: HTTPAuthorizationCredentials | None = Security(user_identity_bearer),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise security_error("AUTH_TOKEN_INVALID")
    token = credentials.credentials.strip()
    if not token:
        raise security_error("AUTH_TOKEN_INVALID")
    return token


def identity_from_token(token: str, settings: Settings) -> AuthenticatedIdentity:
    # Read the unverified issuer only to choose the configured verifier. Authenticity is checked
    # immediately by the selected adapter; no claims from this decode are trusted for authorization.
    try:
        issuer = jwt.decode(token, options={"verify_signature": False}).get("iss")
    except jwt.PyJWTError as exc:
        raise security_error("AUTH_TOKEN_INVALID") from exc
    if issuer == DevMockIdentityProvider.ISSUER:
        if not settings.dev_mock_auth_enabled or settings.app_env not in {
            AppEnvironment.LOCAL,
            AppEnvironment.CI,
            AppEnvironment.DEV,
        }:
            raise security_error("AUTH_TOKEN_INVALID")
        return DevMockIdentityProvider(settings).verify(token)
    return ClerkJwtIdentityProvider(settings).verify(token)


def source_ip(request: Request, settings: Settings = Depends(get_settings)) -> str:
    # This header is trusted only because the Phase-1 deployment boundary is Railway ingress.
    # Deployments that bypass that ingress must not expose this service directly without an
    # equivalent trusted-proxy contract.
    value = request.headers.get(settings.trusted_remote_ip_header)
    if value:
        return value.split(",", 1)[0].strip()
    return request.client.host if request.client else "0.0.0.0"


def repository(
    settings: Settings = Depends(get_settings),
) -> Generator[SecurityRepository, None, None]:
    factory = build_session_factory(settings)
    if factory is None:
        raise security_error("DATABASE_UNAVAILABLE")
    session = factory()
    try:
        yield SecurityRepository(session)
    finally:
        session.close()


def token_service(settings: Settings = Depends(get_settings)) -> TokenService:
    return TokenService(settings)


def network_adapter(settings: Settings = Depends(get_settings)) -> NetworkRiskAdapter:
    if settings.network_risk_mode.lower() == "mock":
        return MockNetworkRiskAdapter(settings.mock_network_risk_status)
    return UnknownNetworkRiskAdapter()
