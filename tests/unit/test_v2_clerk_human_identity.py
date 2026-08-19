from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.security import HTTPAuthorizationCredentials

from verigence_security.adapters.identity import ClerkJwtIdentityProvider
from verigence_security.api.v2_human_dependencies import security_human_user_id
from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError

ISSUER = "https://clerk.example.test"
AUTHORIZED_PARTY = "https://web.example.test"
SUBJECT = "user_test_clerk_subject"


def _keypair() -> tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


def _settings(public_pem: str) -> Settings:
    return Settings(
        clerk_issuer=ISSUER,
        clerk_jwt_key=public_pem,
        clerk_authorized_parties=AUTHORIZED_PARTY,
        security_public_key_pem=public_pem,
    )


def _token(
    private_pem: str,
    *,
    issuer: str = ISSUER,
    authorized_party: str = AUTHORIZED_PARTY,
    expires_delta: timedelta = timedelta(minutes=5),
) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": issuer,
            "sub": SUBJECT,
            "sid": "sess_test",
            "azp": authorized_party,
            "iat": now,
            "exp": now + expires_delta,
        },
        private_pem,
        algorithm="RS256",
    )


def _assert_security_error(exc: pytest.ExceptionInfo[SecurityError], code: str) -> None:
    assert exc.value.code == code


def test_legacy_clerk_identity_provider_accepts_valid_signed_session_jwt() -> None:
    private_pem, public_pem = _keypair()
    identity = ClerkJwtIdentityProvider(_settings(public_pem)).verify(_token(private_pem))

    assert identity.provider == "CLERK"
    assert identity.provider_subject == SUBJECT
    assert identity.session_id == "sess_test"


def test_legacy_clerk_identity_provider_rejects_wrong_signature() -> None:
    signing_private, _ = _keypair()
    _, trusted_public = _keypair()

    with pytest.raises(SecurityError) as exc:
        ClerkJwtIdentityProvider(_settings(trusted_public)).verify(_token(signing_private))

    _assert_security_error(exc, "AUTH_TOKEN_INVALID")


def test_legacy_clerk_identity_provider_rejects_wrong_issuer() -> None:
    private_pem, public_pem = _keypair()

    with pytest.raises(SecurityError) as exc:
        ClerkJwtIdentityProvider(_settings(public_pem)).verify(
            _token(private_pem, issuer="https://other.example.test")
        )

    _assert_security_error(exc, "AUTH_TOKEN_INVALID")


def test_legacy_clerk_identity_provider_rejects_expired_token() -> None:
    private_pem, public_pem = _keypair()

    with pytest.raises(SecurityError) as exc:
        ClerkJwtIdentityProvider(_settings(public_pem)).verify(
            _token(private_pem, expires_delta=timedelta(seconds=-1))
        )

    _assert_security_error(exc, "AUTH_TOKEN_EXPIRED")


def test_legacy_clerk_identity_provider_rejects_unapproved_authorized_party() -> None:
    private_pem, public_pem = _keypair()

    with pytest.raises(SecurityError) as exc:
        ClerkJwtIdentityProvider(_settings(public_pem)).verify(
            _token(private_pem, authorized_party="https://untrusted.example.test")
        )

    _assert_security_error(exc, "AUTH_TOKEN_INVALID")


def test_active_v2_human_dependency_rejects_clerk_session_jwt() -> None:
    private_pem, public_pem = _keypair()
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials=_token(private_pem),
    )

    with pytest.raises(SecurityError) as exc:
        security_human_user_id(credentials=credentials, settings=_settings(public_pem))

    _assert_security_error(exc, "AUTH_TOKEN_INVALID")
