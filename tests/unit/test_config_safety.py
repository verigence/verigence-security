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
            clerk_issuer="x",
            clerk_jwt_key="y",
            database_url="x",
        )


def test_uat_rejects_mock_network_risk():
    with pytest.raises(ValueError):
        Settings(
            app_env="uat",
            dev_mock_auth_enabled=False,
            network_risk_mode="mock",
            clerk_issuer="x",
            clerk_jwt_key="y",
        )


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
