from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlencode

import httpx

from verigence_security.settings import Settings


class UpstreamAuthenticationError(Exception):
    """The configured upstream identity provider rejected or failed authentication."""


class UpstreamConfigurationError(Exception):
    """The upstream identity-provider configuration is incomplete."""


@dataclass(frozen=True)
class ExternalIdentity:
    subject: str
    email: str | None = None


class UpstreamIdentityProvider(Protocol):
    def authorization_url(self, *, state: str) -> str: ...

    async def authenticate_code(self, *, code: str) -> ExternalIdentity: ...


class ClerkOAuthProvider:
    """Use Clerk as the upstream OAuth/OIDC identity provider behind Security."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def authorization_url(self, *, state: str) -> str:
        self._require_configured()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.settings.clerk_oauth_client_id,
                "redirect_uri": self.settings.clerk_oauth_redirect_uri,
                "scope": "openid profile email",
                "state": state,
            }
        )
        return f"{self.settings.clerk_oauth_authorize_url}?{query}"

    async def authenticate_code(self, *, code: str) -> ExternalIdentity:
        self._require_configured()
        timeout = httpx.Timeout(10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            try:
                token_response = await client.post(
                    self.settings.clerk_oauth_token_url,
                    auth=(
                        self.settings.clerk_oauth_client_id,
                        self.settings.clerk_oauth_client_secret,
                    ),
                    data={
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": self.settings.clerk_oauth_redirect_uri,
                    },
                )
            except httpx.HTTPError as exc:
                raise UpstreamAuthenticationError("upstream token exchange failed") from exc

            if token_response.status_code != 200:
                raise UpstreamAuthenticationError("upstream token exchange was denied")
            payload = token_response.json()
            access_token = payload.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise UpstreamAuthenticationError("upstream token response has no access token")

            try:
                userinfo_response = await client.get(
                    self.settings.clerk_oauth_userinfo_url,
                    headers={"Authorization": f"Bearer {access_token}"},
                )
            except httpx.HTTPError as exc:
                raise UpstreamAuthenticationError("upstream userinfo request failed") from exc

            if userinfo_response.status_code != 200:
                raise UpstreamAuthenticationError("upstream userinfo request was denied")
            userinfo = userinfo_response.json()

        subject = userinfo.get("sub") or userinfo.get("user_id")
        if not isinstance(subject, str) or not subject:
            raise UpstreamAuthenticationError("upstream identity has no subject")
        email = userinfo.get("email")
        return ExternalIdentity(subject=subject, email=email if isinstance(email, str) else None)

    def _require_configured(self) -> None:
        values = (
            self.settings.clerk_oauth_authorize_url,
            self.settings.clerk_oauth_token_url,
            self.settings.clerk_oauth_userinfo_url,
            self.settings.clerk_oauth_client_id,
            self.settings.clerk_oauth_client_secret,
            self.settings.clerk_oauth_redirect_uri,
        )
        if not all(values):
            raise UpstreamConfigurationError("Clerk OAuth configuration is incomplete")
