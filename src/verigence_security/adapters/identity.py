from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

import jwt

from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.core.types import AppEnvironment


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    provider: str
    provider_subject: str
    session_id: str


class UserIdentityProvider(Protocol):
    def verify(self, token: str) -> AuthenticatedIdentity: ...


class ClerkJwtIdentityProvider:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def verify(self, token: str) -> AuthenticatedIdentity:
        try:
            claims = jwt.decode(
                token,
                self.settings.clerk_jwt_key,
                algorithms=["RS256"],
                issuer=self.settings.clerk_issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc
        azp = claims.get("azp")
        allowed = self.settings.clerk_authorized_party_list
        if allowed and azp not in allowed:
            raise security_error("AUTH_TOKEN_INVALID", "Token authorized party is not allowed")
        return AuthenticatedIdentity("CLERK", str(claims["sub"]), str(claims.get("sid", "")))


class DevMockIdentityProvider:
    ISSUER = "verigence-security-dev-mock"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def issue(self, provider_subject: str) -> tuple[str, datetime]:
        if not self.settings.dev_mock_auth_enabled or self.settings.app_env not in {
            AppEnvironment.LOCAL,
            AppEnvironment.CI,
            AppEnvironment.DEV,
        }:
            raise security_error("AUTH_TOKEN_INVALID")
        ttl_minutes = self.settings.dev_mock_token_ttl_minutes
        if not self.settings.dev_mock_signing_secret or ttl_minutes is None:
            raise security_error("AUTH_TOKEN_INVALID")
        now = datetime.now(UTC)
        exp = now + timedelta(minutes=ttl_minutes)
        token = jwt.encode(
            {
                "iss": self.ISSUER,
                "sub": provider_subject,
                "sid": f"mock_{uuid4()}",
                "iat": now,
                "exp": exp,
            },
            self.settings.dev_mock_signing_secret,
            algorithm="HS256",
        )
        return token, exp

    def verify(self, token: str) -> AuthenticatedIdentity:
        if not self.settings.dev_mock_auth_enabled or not self.settings.dev_mock_signing_secret:
            raise security_error("AUTH_TOKEN_INVALID")
        try:
            claims = jwt.decode(
                token,
                self.settings.dev_mock_signing_secret,
                algorithms=["HS256"],
                issuer=self.ISSUER,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc
        return AuthenticatedIdentity("DEV_MOCK", str(claims["sub"]), str(claims.get("sid", "")))
