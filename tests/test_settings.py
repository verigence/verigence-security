from __future__ import annotations

import json

from verigence_security.settings import Settings


def test_from_env_accepts_existing_railway_security_names(monkeypatch, settings):
    monkeypatch.delenv("SECURITY_JWT_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.setenv("SECURITY_PRIVATE_KEY_PEM", settings.private_key_pem)
    monkeypatch.setenv("SECURITY_KEY_ID", "legacy-kid")
    monkeypatch.setenv("SECURITY_TOKEN_ISSUER", "verigence-security")
    monkeypatch.setenv("SECURITY_TOKEN_AUDIENCE", "verigence-platform")
    monkeypatch.setenv("DATABASE_URL", "postgresql://example.invalid/security")
    monkeypatch.setenv(
        "SECURITY_INTEGRATION_CLIENTS_JSON",
        json.dumps(
            {
                "audit-core": {
                    "secret_sha256": "a" * 64,
                    "permissions": ["di.document.read"],
                    "redirect_uris": ["https://audit-core.test/oauth/callback"],
                }
            }
        ),
    )

    resolved = Settings.from_env()

    assert resolved.private_key_pem == settings.private_key_pem
    assert resolved.key_id == "legacy-kid"
    assert resolved.issuer == "verigence-security"
    assert resolved.audience == "verigence-platform"
    assert resolved.role_database_url == "postgresql://example.invalid/security"
    assert resolved.integration_clients["audit-core"].secret_sha256 == "a" * 64
