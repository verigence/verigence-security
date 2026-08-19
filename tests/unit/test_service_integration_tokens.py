from __future__ import annotations

import hashlib
from datetime import datetime

import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from verigence_security.config import Settings
from verigence_security.core.errors import SecurityError
from verigence_security.repositories.service_integration_repository import ServiceIntegrationCredential
from verigence_security.services.service_integration_tokens import ServiceIntegrationTokenService
from verigence_security.services.token_service import TokenService

_PASSWORD_HASHER = PasswordHasher()


class FakeServiceRepository:
    def __init__(self, credential: ServiceIntegrationCredential) -> None:
        self.credential = credential
        self.used_credential_id: str | None = None
        self.committed = False
        self.rolled_back = False

    def active_credential(self, client_id: str, now: datetime) -> ServiceIntegrationCredential:
        _ = now
        if client_id != self.credential.client_id:
            raise AssertionError("unexpected client_id")
        return self.credential

    @staticmethod
    def audience_is_registered(audience: str) -> bool:
        return audience in {"security", "di", "audit"}

    def mark_credential_used(self, credential_id: str, now: datetime) -> None:
        _ = now
        self.used_credential_id = credential_id

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True


def _token_service() -> TokenService:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return TokenService(
        Settings(
            app_env="ci",
            security_key_id="test-service-key",
            security_private_key_pem=private_pem,
            security_public_key_pem=public_pem,
        )
    )


def _credential(secret_hash: str) -> ServiceIntegrationCredential:
    return ServiceIntegrationCredential(
        principal_id="00000000-0000-4000-8000-000000000001",
        integration_key="audit-core",
        credential_id="00000000-0000-4000-8000-000000000002",
        client_id="audit-core-client",
        secret_hash=secret_hash,
    )


def test_service_token_is_four_hours_platform_global_and_audience_bound() -> None:
    tokens = _token_service()
    repo = FakeServiceRepository(_credential(_PASSWORD_HASHER.hash("correct-secret")))
    service = ServiceIntegrationTokenService(repo, tokens)  # type: ignore[arg-type]

    result = service.issue(
        client_id="audit-core-client",
        client_secret="correct-secret",
        audience="di",
    )
    claims = tokens.verify_service_token(result.access_token, audience="di")

    assert claims["sub"] == "audit-core"
    assert claims["actor_type"] == "SERVICE_INTEGRATION"
    assert claims["aud"] == "di"
    assert int(claims["exp"]) - int(claims["iat"]) == 4 * 60 * 60
    assert "tenant_id" not in claims
    assert "permissions" not in claims
    assert "roles" not in claims
    assert "access_session_id" not in claims
    assert repo.used_credential_id == repo.credential.credential_id
    assert repo.committed is True

    with pytest.raises(SecurityError) as exc_info:
        tokens.verify_service_token(result.access_token, audience="security")
    assert exc_info.value.code == "AUTH_TOKEN_INVALID"


def test_service_token_rejects_wrong_secret_and_unregistered_audience() -> None:
    tokens = _token_service()
    repo = FakeServiceRepository(_credential(_PASSWORD_HASHER.hash("correct-secret")))
    service = ServiceIntegrationTokenService(repo, tokens)  # type: ignore[arg-type]

    with pytest.raises(SecurityError) as exc_info:
        service.issue(
            client_id="audit-core-client",
            client_secret="wrong-secret",
            audience="di",
        )
    assert exc_info.value.code == "MACHINE_CREDENTIAL_INVALID"
    assert repo.rolled_back is True

    with pytest.raises(ValueError, match="audience"):
        service.issue(
            client_id="audit-core-client",
            client_secret="correct-secret",
            audience="external-system",
        )


def test_service_token_accepts_existing_sha256_credential_during_migration() -> None:
    tokens = _token_service()
    legacy_hash = hashlib.sha256(b"legacy-secret").hexdigest()
    repo = FakeServiceRepository(_credential(legacy_hash))
    service = ServiceIntegrationTokenService(repo, tokens)  # type: ignore[arg-type]

    result = service.issue(
        client_id="audit-core-client",
        client_secret="legacy-secret",
        audience="security",
    )
    claims = tokens.verify_service_token(result.access_token, audience="security")
    assert claims["sub"] == "audit-core"
    assert claims["aud"] == "security"
