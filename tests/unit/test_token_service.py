from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from verigence_security.config import Settings
from verigence_security.core.types import ActorType
from verigence_security.services.token_service import AccessTokenClaims, TokenService


def _pem_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def _settings(private_pem: str, public_pem: str) -> Settings:
    return Settings(
        app_env="dev",
        security_key_id="key-1",
        security_private_key_pem=private_pem,
        security_public_key_pem=public_pem,
    )


def test_signing_key_readiness_requires_matching_key_pair():
    private_one, public_one = _pem_pair()
    _, public_two = _pem_pair()
    assert TokenService(_settings(private_one, public_one)).signing_key_ready()
    assert not TokenService(_settings(private_one, public_two)).signing_key_ready()


def test_token_issue_and_verify_preserves_security_asserted_actor_and_permissions():
    private_pem, public_pem = _pem_pair()
    service = TokenService(_settings(private_pem, public_pem))
    expires = datetime.now(UTC) + timedelta(minutes=5)

    token = service.issue(
        AccessTokenClaims(
            principal_id="11111111-1111-1111-1111-111111111111",
            actor_type=ActorType.USER,
            tenant_id="22222222-2222-2222-2222-222222222222",
            access_session_id="33333333-3333-3333-3333-333333333333",
            permissions=("di.document.read", "di.document.upload"),
            roles=("PC",),
            device_id="44444444-4444-4444-4444-444444444444",
            location_id="55555555-5555-5555-5555-555555555555",
            expires_at=expires,
        )
    )
    claims = service.verify(token)

    assert claims["actor_type"] == "USER"
    assert claims["permissions"] == ["di.document.read", "di.document.upload"]
    assert claims["device_id"] == "44444444-4444-4444-4444-444444444444"
    assert claims["location_id"] == "55555555-5555-5555-5555-555555555555"


def test_legacy_permission_is_never_emitted_in_security_token():
    private_pem, public_pem = _pem_pair()
    service = TokenService(_settings(private_pem, public_pem))

    with pytest.raises(ValueError):
        service.issue(
            AccessTokenClaims(
                principal_id="11111111-1111-1111-1111-111111111111",
                actor_type=ActorType.USER,
                tenant_id="22222222-2222-2222-2222-222222222222",
                access_session_id="33333333-3333-3333-3333-333333333333",
                permissions=("document:upload",),
                roles=("PC",),
                device_id="44444444-4444-4444-4444-444444444444",
                location_id="55555555-5555-5555-5555-555555555555",
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        )
