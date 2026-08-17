import pytest

from verigence_security.config import Settings


def test_prod_rejects_mock_auth():
    with pytest.raises(ValueError):
        Settings(
            app_env="production",
            dev_mock_auth_enabled=True,
            dev_mock_signing_secret="dev-secret",
            dev_mock_token_ttl_minutes=10,
            network_risk_mode="real",
            clerk_secret_key="backend-secret",
            database_url="x",
        )


def test_uat_rejects_mock_network_risk():
    with pytest.raises(ValueError):
        Settings(
            app_env="uat",
            dev_mock_auth_enabled=False,
            network_risk_mode="mock",
            clerk_secret_key="backend-secret",
        )


def test_protected_env_requires_clerk_backend_secret():
    with pytest.raises(ValueError, match="Clerk Backend secret key"):
        Settings(
            app_env="uat",
            dev_mock_auth_enabled=False,
            network_risk_mode="real",
        )


def test_uat_backend_auth_does_not_require_client_clerk_jwt_settings():
    settings = Settings(
        app_env="uat",
        dev_mock_auth_enabled=False,
        network_risk_mode="real",
        clerk_secret_key="backend-secret",
    )
    assert settings.clerk_secret_key == "backend-secret"
    assert settings.clerk_issuer == ""
    assert settings.clerk_jwt_key == ""


def test_dev_mock_requires_explicit_signing_secret():
    with pytest.raises(ValueError):
        Settings(
            app_env="dev",
            dev_mock_auth_enabled=True,
            dev_mock_token_ttl_minutes=10,
        )


def test_dev_mock_requires_explicit_token_ttl():
    with pytest.raises(ValueError):
        Settings(
            app_env="dev",
            dev_mock_auth_enabled=True,
            dev_mock_signing_secret="dev-secret",
        )
