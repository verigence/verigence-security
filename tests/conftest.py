from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from verigence_security.settings import IntegrationClient, Settings


@pytest.fixture
def settings() -> Settings:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return Settings(
        private_key_pem=private_key,
        key_id="test-key",
        issuer="verigence-security",
        audience="verigence-platform",
        token_ttl_seconds=300,
        role_permission_bundles={},
        integration_clients={
            "audit-core": IntegrationClient(
                secret="audit-core-secret",
                permissions=frozenset(
                    {
                        "di.subject.create",
                        "di.subject.read",
                        "di.document.upload",
                        "di.document.read",
                        "di.document.content.read",
                        "di.document.fields.read",
                        "di.document.quality.read",
                        "di.entity_link.read",
                        "di.entity_link.write",
                        "di.verification.read",
                        "di.verification.write",
                        "di.operations.read",
                    }
                ),
            )
        },
        role_database_url=None,
    )
