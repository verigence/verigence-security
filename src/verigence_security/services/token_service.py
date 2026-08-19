from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from verigence_security.config import Settings
from verigence_security.core.errors import security_error
from verigence_security.core.types import ActorType
from verigence_security.services.permissions import validate_permissions


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True, slots=True)
class AccessTokenClaims:
    principal_id: str
    actor_type: ActorType
    tenant_id: str
    access_session_id: str
    permissions: tuple[str, ...]
    expires_at: datetime
    roles: tuple[str, ...] = ()
    device_id: str | None = None
    location_id: str | None = None
    delegated_actor_id: str | None = None
    subject: str | None = None


@dataclass(frozen=True, slots=True)
class HumanTokenClaims:
    user_id: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ServiceTokenClaims:
    subject: str
    audience: str
    expires_at: datetime


def _validate_actor_claim_shape(claims: AccessTokenClaims) -> None:
    if claims.actor_type == ActorType.USER:
        if not claims.device_id or not claims.location_id or not claims.roles:
            raise ValueError("USER Security token requires roles, device_id and location_id")
        if claims.subject is not None and claims.subject != claims.principal_id:
            raise ValueError("USER Security token subject must identify the USER principal")
        return
    if claims.roles or claims.device_id or claims.location_id:
        raise ValueError(
            "Machine Security token cannot carry USER-only roles/device/location claims"
        )
    if claims.delegated_actor_id is not None:
        raise ValueError("Machine Security token cannot carry a delegated USER actor claim")
    if claims.subject is not None and not claims.subject:
        raise ValueError("Machine Security token subject cannot be empty")


class TokenService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def issue(self, claims: AccessTokenClaims) -> str:
        if not self.settings.security_private_key_pem or not self.settings.security_key_id:
            raise security_error("SIGNING_KEY_UNAVAILABLE")

        _validate_actor_claim_shape(claims)
        # Security is the canonical permission catalogue owner. Never emit a legacy/invalid
        # permission string even if bad data somehow reached the database.
        permissions = validate_permissions(list(claims.permissions))

        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": self.settings.security_token_issuer,
            "sub": claims.subject or claims.principal_id,
            "aud": self.settings.security_token_audience,
            "iat": now,
            "exp": claims.expires_at,
            "jti": str(uuid4()),
            "actor_type": claims.actor_type.value,
            "tenant_id": claims.tenant_id,
            "access_session_id": claims.access_session_id,
            "permissions": permissions,
        }
        if claims.roles:
            payload["roles"] = list(claims.roles)
        if claims.device_id:
            payload["device_id"] = claims.device_id
        if claims.location_id:
            payload["location_id"] = claims.location_id
        if claims.delegated_actor_id:
            payload["act"] = {"sub": claims.delegated_actor_id}
        try:
            return jwt.encode(
                payload,
                self.settings.security_private_key_pem,
                algorithm="RS256",
                headers={"kid": self.settings.security_key_id},
            )
        except (ValueError, TypeError, jwt.PyJWTError) as exc:
            raise security_error("SIGNING_KEY_UNAVAILABLE") from exc

    def issue_human_token(self, claims: HumanTokenClaims) -> str:
        """Issue the active Phase-1 global USER authentication token.

        This token deliberately carries no Tenant, role, permission, device, location or legacy
        access-session authority. Those decisions remain live Security state.
        """

        if not self.settings.security_private_key_pem or not self.settings.security_key_id:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        if not claims.user_id.strip():
            raise ValueError("Human token USER id is required")

        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": self.settings.security_token_issuer,
            "sub": claims.user_id,
            "aud": self.settings.security_token_audience,
            "iat": now,
            "exp": claims.expires_at,
            "jti": str(uuid4()),
            "actor_type": ActorType.USER.value,
        }
        try:
            return jwt.encode(
                payload,
                self.settings.security_private_key_pem,
                algorithm="RS256",
                headers={"kid": self.settings.security_key_id},
            )
        except (ValueError, TypeError, jwt.PyJWTError) as exc:
            raise security_error("SIGNING_KEY_UNAVAILABLE") from exc

    def issue_service_token(self, claims: ServiceTokenClaims) -> str:
        if not self.settings.security_private_key_pem or not self.settings.security_key_id:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        if not claims.subject.strip() or not claims.audience.strip():
            raise ValueError("Service token subject and audience are required")

        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            "iss": self.settings.security_token_issuer,
            "sub": claims.subject,
            "aud": claims.audience,
            "iat": now,
            "exp": claims.expires_at,
            "jti": str(uuid4()),
            "actor_type": ActorType.SERVICE_INTEGRATION.value,
        }
        try:
            return jwt.encode(
                payload,
                self.settings.security_private_key_pem,
                algorithm="RS256",
                headers={"kid": self.settings.security_key_id},
            )
        except (ValueError, TypeError, jwt.PyJWTError) as exc:
            raise security_error("SIGNING_KEY_UNAVAILABLE") from exc

    def verify_human_token(self, token: str) -> dict[str, Any]:
        """Validate a Security-issued human token for the active v2 human boundary.

        The token proves the global USER identity only. Roles, permissions, Tenant context and
        other legacy session claims are deliberately not trusted here; protected operations
        resolve current authorization from Security-owned state after token verification.
        """

        if not self.settings.security_public_key_pem:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        try:
            payload = jwt.decode(
                token,
                self.settings.security_public_key_pem,
                algorithms=["RS256"],
                issuer=self.settings.security_token_issuer,
                audience=self.settings.security_token_audience,
                options={
                    "require": ["exp", "iat", "sub", "jti", "actor_type"]
                },
            )
            if payload.get("actor_type") != ActorType.USER.value:
                raise security_error("ACTOR_TYPE_NOT_ALLOWED")
            if not isinstance(payload.get("sub"), str) or not str(payload["sub"]).strip():
                raise security_error("AUTH_TOKEN_INVALID")
            # Token exchange is a retired/deferred human path. A delegated USER token must not
            # enter the direct human administrative boundary.
            if "act" in payload:
                raise security_error("AUTH_TOKEN_INVALID")
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc

    def verify(self, token: str) -> dict[str, Any]:
        if not self.settings.security_public_key_pem:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        try:
            payload = jwt.decode(
                token,
                self.settings.security_public_key_pem,
                algorithms=["RS256"],
                issuer=self.settings.security_token_issuer,
                audience=self.settings.security_token_audience,
                options={
                    "require": [
                        "exp",
                        "iat",
                        "sub",
                        "jti",
                        "actor_type",
                        "tenant_id",
                        "access_session_id",
                        "permissions",
                    ]
                },
            )
            try:
                actor_type = ActorType(str(payload["actor_type"]))
            except ValueError as exc:
                raise security_error("AUTH_TOKEN_INVALID") from exc
            if actor_type == ActorType.USER:
                if (
                    not payload.get("device_id")
                    or not payload.get("location_id")
                    or not payload.get("roles")
                ):
                    raise security_error("AUTH_TOKEN_INVALID")
            elif payload.get("device_id") or payload.get("location_id") or payload.get("roles"):
                raise security_error("AUTH_TOKEN_INVALID")

            delegated_actor = payload.get("act")
            if delegated_actor is not None:
                if actor_type != ActorType.USER:
                    raise security_error("AUTH_TOKEN_INVALID")
                if (
                    not isinstance(delegated_actor, dict)
                    or not isinstance(delegated_actor.get("sub"), str)
                    or not delegated_actor["sub"]
                ):
                    raise security_error("AUTH_TOKEN_INVALID")

            try:
                validate_permissions([str(value) for value in payload.get("permissions", [])])
            except ValueError as exc:
                raise security_error("AUTH_TOKEN_INVALID") from exc
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc

    def verify_service_token(self, token: str, *, audience: str) -> dict[str, Any]:
        if not self.settings.security_public_key_pem:
            raise security_error("SIGNING_KEY_UNAVAILABLE")
        if not audience.strip():
            raise security_error("AUTH_TOKEN_INVALID")
        try:
            payload = jwt.decode(
                token,
                self.settings.security_public_key_pem,
                algorithms=["RS256"],
                issuer=self.settings.security_token_issuer,
                audience=audience,
                options={
                    "require": ["exp", "iat", "sub", "jti", "actor_type", "aud"]
                },
            )
            if payload.get("actor_type") != ActorType.SERVICE_INTEGRATION.value:
                raise security_error("ACTOR_TYPE_NOT_ALLOWED")
            forbidden_claims = {
                "tenant_id",
                "access_session_id",
                "permissions",
                "roles",
                "device_id",
                "location_id",
                "act",
            }
            if forbidden_claims.intersection(payload):
                raise security_error("AUTH_TOKEN_INVALID")
            if not isinstance(payload.get("sub"), str) or not str(payload["sub"]).strip():
                raise security_error("AUTH_TOKEN_INVALID")
            return payload
        except jwt.ExpiredSignatureError as exc:
            raise security_error("AUTH_TOKEN_EXPIRED") from exc
        except jwt.PyJWTError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc

    def jwks(self) -> dict[str, object]:
        if not self.settings.security_public_key_pem or not self.settings.security_key_id:
            return {"keys": []}
        try:
            key = serialization.load_pem_public_key(self.settings.security_public_key_pem.encode())
        except (TypeError, ValueError) as exc:
            raise security_error("SIGNING_KEY_UNAVAILABLE") from exc
        if not isinstance(key, RSAPublicKey):
            raise security_error("SIGNING_KEY_UNAVAILABLE", "Configured signing key is not RSA")
        numbers = key.public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": self.settings.security_key_id,
                    "n": _b64url_uint(numbers.n),
                    "e": _b64url_uint(numbers.e),
                }
            ]
        }

    def signing_key_ready(self) -> bool:
        if not (
            self.settings.security_private_key_pem
            and self.settings.security_public_key_pem
            and self.settings.security_key_id
        ):
            return False
        try:
            public_key = serialization.load_pem_public_key(
                self.settings.security_public_key_pem.encode()
            )
            private_key = serialization.load_pem_private_key(
                self.settings.security_private_key_pem.encode(),
                password=None,
            )
        except (TypeError, ValueError):
            return False
        if not isinstance(public_key, RSAPublicKey) or not isinstance(private_key, RSAPrivateKey):
            return False
        return private_key.public_key().public_numbers() == public_key.public_numbers()
