from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class IntegrationClient:
    secret: str
    permissions: frozenset[str]
    redirect_uris: frozenset[str] = field(default_factory=frozenset)
    public: bool = False


@dataclass(frozen=True)
class Settings:
    private_key_pem: str
    key_id: str
    issuer: str
    audience: str
    token_ttl_seconds: int
    role_permission_bundles: dict[str, frozenset[str]]
    integration_clients: dict[str, IntegrationClient]
    role_database_url: str | None = None
    session_ttl_seconds: int = 28800
    authorization_code_ttl_seconds: int = 300
    authorization_request_ttl_seconds: int = 600
    session_cookie_name: str = "verigence_session"
    session_cookie_secure: bool = True
    clerk_oauth_authorize_url: str = ""
    clerk_oauth_token_url: str = ""
    clerk_oauth_userinfo_url: str = ""
    clerk_oauth_client_id: str = ""
    clerk_oauth_client_secret: str = ""
    clerk_oauth_redirect_uri: str = ""

    @classmethod
    def from_env(cls) -> Settings:
        private_key = os.environ.get("SECURITY_JWT_PRIVATE_KEY_PEM", "").replace("\\n", "\n")
        if not private_key:
            raise RuntimeError("SECURITY_JWT_PRIVATE_KEY_PEM is required")

        return cls(
            private_key_pem=private_key,
            key_id=os.environ.get("SECURITY_JWT_KID", "security-1"),
            issuer=os.environ.get("SECURITY_JWT_ISSUER", "verigence-security"),
            audience=os.environ.get("SECURITY_JWT_AUDIENCE", "verigence-platform"),
            token_ttl_seconds=int(os.environ.get("SECURITY_TOKEN_TTL_SECONDS", "300")),
            role_permission_bundles=_load_role_bundles(
                os.environ.get("SECURITY_ROLE_PERMISSION_BUNDLES_JSON", "{}")
            ),
            integration_clients=_load_integration_clients(
                os.environ.get("SECURITY_INTEGRATION_CLIENTS_JSON", "{}")
            ),
            role_database_url=os.environ.get("SECURITY_ROLE_DATABASE_URL") or None,
            session_ttl_seconds=int(os.environ.get("SECURITY_SESSION_TTL_SECONDS", "28800")),
            authorization_code_ttl_seconds=int(
                os.environ.get("SECURITY_AUTHORIZATION_CODE_TTL_SECONDS", "300")
            ),
            authorization_request_ttl_seconds=int(
                os.environ.get("SECURITY_AUTHORIZATION_REQUEST_TTL_SECONDS", "600")
            ),
            session_cookie_name=os.environ.get(
                "SECURITY_SESSION_COOKIE_NAME", "verigence_session"
            ),
            session_cookie_secure=_env_bool("SECURITY_SESSION_COOKIE_SECURE", True),
            clerk_oauth_authorize_url=os.environ.get("CLERK_OAUTH_AUTHORIZE_URL", ""),
            clerk_oauth_token_url=os.environ.get("CLERK_OAUTH_TOKEN_URL", ""),
            clerk_oauth_userinfo_url=os.environ.get("CLERK_OAUTH_USERINFO_URL", ""),
            clerk_oauth_client_id=os.environ.get("CLERK_OAUTH_CLIENT_ID", ""),
            clerk_oauth_client_secret=os.environ.get("CLERK_OAUTH_CLIENT_SECRET", ""),
            clerk_oauth_redirect_uri=os.environ.get("CLERK_OAUTH_REDIRECT_URI", ""),
        )


def _load_role_bundles(raw: str) -> dict[str, frozenset[str]]:
    data: dict[str, Any] = json.loads(raw)
    return {
        role: frozenset(_string_list(permissions, f"role {role} permissions"))
        for role, permissions in data.items()
    }


def _load_integration_clients(raw: str) -> dict[str, IntegrationClient]:
    data: dict[str, Any] = json.loads(raw)
    clients: dict[str, IntegrationClient] = {}
    for client_id, config in data.items():
        if not isinstance(config, dict):
            raise TypeError(f"integration client {client_id} must be an object")
        secret = config.get("secret", "")
        public = bool(config.get("public", False))
        if not public and (not isinstance(secret, str) or not secret):
            raise ValueError(f"integration client {client_id} requires a secret")
        if not isinstance(secret, str):
            raise TypeError(f"integration client {client_id} secret must be a string")
        clients[client_id] = IntegrationClient(
            secret=secret,
            permissions=frozenset(
                _string_list(config.get("permissions", []), f"client {client_id} permissions")
            ),
            redirect_uris=frozenset(
                _string_list(config.get("redirect_uris", []), f"client {client_id} redirect_uris")
            ),
            public=public,
        )
    return clients


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must be a list of non-empty strings")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
