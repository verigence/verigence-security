from __future__ import annotations

import base64
import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from verigence_security.settings import Settings


class TokenError(Exception):
    """Base token-service error."""


class InvalidToken(TokenError):
    """The supplied subject token is invalid."""


class PermissionDenied(TokenError):
    """Requested downstream permission is not authorized."""


class UnknownRole(TokenError):
    """A role has no configured permission bundle."""


@dataclass(frozen=True)
class IssuedToken:
    access_token: str
    expires_in: int
    scope: str


class TokenService:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._private_key = serialization.load_pem_private_key(
            settings.private_key_pem.encode("utf-8"), password=None
        )
        self._public_key = self._private_key.public_key()

    def effective_permissions(
        self, roles: Iterable[str], direct_permissions: Iterable[str] = ()
    ) -> frozenset[str]:
        permissions = set(direct_permissions)
        for role in roles:
            bundle = self.settings.role_permission_bundles.get(role)
            if bundle is None:
                raise UnknownRole(role)
            permissions.update(bundle)
        return frozenset(permissions)

    def issue_user_access_token(
        self,
        *,
        subject: str,
        tenant_id: str,
        roles: Iterable[str],
        direct_permissions: Iterable[str] = (),
    ) -> IssuedToken:
        role_list = list(roles)
        permissions = self.effective_permissions(role_list, direct_permissions)
        return self._issue(
            subject=subject,
            tenant_id=tenant_id,
            actor_type="USER",
            roles=role_list,
            permissions=permissions,
        )

    def issue_service_token(
        self,
        *,
        client_id: str,
        tenant_id: str,
        requested_permissions: Iterable[str],
    ) -> IssuedToken:
        requested = _required_permission_set(requested_permissions)
        allowed = self._client_permissions(client_id)
        if not requested.issubset(allowed):
            raise PermissionDenied("requested service permission is not allowed")
        return self._issue(
            subject=client_id,
            tenant_id=tenant_id,
            actor_type="SERVICE",
            roles=[],
            permissions=requested,
        )

    def exchange_user_token(
        self,
        *,
        client_id: str,
        subject_token: str,
        requested_permissions: Iterable[str],
    ) -> IssuedToken:
        requested = _required_permission_set(requested_permissions)
        claims = self.decode(subject_token)
        if claims.get("actor_type") != "USER":
            raise InvalidToken("subject token is not a user token")

        subject = claims.get("sub")
        tenant_id = claims.get("tenant_id")
        user_permissions = claims.get("permissions")
        if not isinstance(subject, str) or not subject:
            raise InvalidToken("subject token has no subject")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise InvalidToken("subject token has no tenant")
        if not isinstance(user_permissions, list) or not all(
            isinstance(permission, str) for permission in user_permissions
        ):
            raise InvalidToken("subject token has invalid permissions")

        allowed = set(user_permissions).intersection(self._client_permissions(client_id))
        if not requested.issubset(allowed):
            raise PermissionDenied("requested delegated permission is not allowed")

        roles = claims.get("roles", [])
        if not isinstance(roles, list):
            roles = []
        return self._issue(
            subject=subject,
            tenant_id=tenant_id,
            actor_type="USER",
            roles=[role for role in roles if isinstance(role, str)],
            permissions=requested,
            extra_claims={"act": {"sub": client_id}},
        )

    def decode(self, token: str) -> dict:
        try:
            return jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                audience=self.settings.audience,
                issuer=self.settings.issuer,
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken("invalid or expired subject token") from exc

    def jwks(self) -> dict:
        public_numbers = self._public_key.public_numbers()
        if not isinstance(public_numbers, rsa.RSAPublicNumbers):
            raise TypeError("RS256 requires an RSA key")
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.settings.key_id,
                    "n": _base64url_uint(public_numbers.n),
                    "e": _base64url_uint(public_numbers.e),
                }
            ]
        }

    def _client_permissions(self, client_id: str) -> frozenset[str]:
        client = self.settings.integration_clients.get(client_id)
        if client is None:
            raise PermissionDenied("unknown integration client")
        return client.permissions

    def _issue(
        self,
        *,
        subject: str,
        tenant_id: str,
        actor_type: str,
        roles: list[str],
        permissions: Iterable[str],
        extra_claims: dict | None = None,
    ) -> IssuedToken:
        now = int(time.time())
        ttl = self.settings.token_ttl_seconds
        permission_list = sorted(set(permissions))
        claims = {
            "iss": self.settings.issuer,
            "aud": self.settings.audience,
            "sub": subject,
            "tenant_id": tenant_id,
            "actor_type": actor_type,
            "roles": roles,
            "permissions": permission_list,
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_urlsafe(18),
        }
        if extra_claims:
            claims.update(extra_claims)
        token = jwt.encode(
            claims,
            self._private_key,
            algorithm="RS256",
            headers={"kid": self.settings.key_id},
        )
        return IssuedToken(
            access_token=token,
            expires_in=ttl,
            scope=" ".join(permission_list),
        )


def _required_permission_set(permissions: Iterable[str]) -> frozenset[str]:
    requested = frozenset(permission for permission in permissions if permission)
    if not requested:
        raise PermissionDenied("at least one downstream permission is required")
    return requested


def _base64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
