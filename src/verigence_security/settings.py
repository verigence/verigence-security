from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IntegrationClient:
    secret: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class Settings:
    private_key_pem: str
    key_id: str
    issuer: str
    audience: str
    token_ttl_seconds: int
    role_permission_bundles: dict[str, frozenset[str]]
    integration_clients: dict[str, IntegrationClient]

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
        secret = config.get("secret")
        if not isinstance(secret, str) or not secret:
            raise ValueError(f"integration client {client_id} requires a secret")
        clients[client_id] = IntegrationClient(
            secret=secret,
            permissions=frozenset(
                _string_list(config.get("permissions", []), f"client {client_id} permissions")
            ),
        )
    return clients


def _string_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must be a list of non-empty strings")
    return value
