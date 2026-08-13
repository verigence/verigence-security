from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from verigence_security.core.types import AppEnvironment, VpnStatus


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    app_env: AppEnvironment = AppEnvironment.DEV
    app_name: str = "verigence-security"
    log_level: str = "INFO"

    database_url: str = ""
    migration_database_url: str = ""

    clerk_issuer: str = ""
    clerk_jwt_key: str = ""
    clerk_authorized_parties: str = ""

    security_token_issuer: str = "verigence-security"
    security_token_audience: str = "verigence-platform"
    security_key_id: str = ""
    security_private_key_pem: str = ""
    security_public_key_pem: str = ""

    platform_bootstrap_enabled: bool = False
    platform_bootstrap_login: str = ""
    platform_bootstrap_password: str = ""
    platform_admin_token_ttl_minutes: int | None = Field(default=None, gt=0)

    dev_mock_auth_enabled: bool = False
    dev_mock_signing_secret: str = ""
    dev_mock_token_ttl_minutes: int | None = Field(default=None, gt=0)

    network_risk_mode: str = "mock"
    mock_network_risk_status: VpnStatus = VpnStatus.NOT_DETECTED
    trusted_remote_ip_header: str = "X-Real-IP"

    @field_validator(
        "security_private_key_pem",
        "security_public_key_pem",
        "clerk_jwt_key",
        mode="before",
    )
    @classmethod
    def normalize_pem(cls, value: object) -> object:
        if isinstance(value, str):
            return value.replace("\\n", "\n")
        return value

    @model_validator(mode="after")
    def safety_rules(self) -> Settings:
        protected = {AppEnvironment.UAT, AppEnvironment.PRODUCTION}
        if self.app_env in protected and self.dev_mock_auth_enabled:
            raise ValueError("DEV mock authentication is prohibited in UAT/production")
        if self.app_env in protected and self.network_risk_mode.lower() == "mock":
            raise ValueError("Mock network-risk adapter is prohibited in UAT/production")
        if self.app_env in protected and (not self.clerk_issuer or not self.clerk_jwt_key):
            raise ValueError("Clerk issuer and public key are required in UAT/production")
        if self.app_env == AppEnvironment.PRODUCTION and not self.database_url:
            raise ValueError("DATABASE_URL is required in production")
        if self.dev_mock_auth_enabled:
            if not self.dev_mock_signing_secret:
                raise ValueError("DEV mock signing secret is required when mock auth is enabled")
            if self.dev_mock_token_ttl_minutes is None:
                raise ValueError("DEV mock token TTL is required when mock auth is enabled")
        if self.platform_bootstrap_enabled:
            if self.app_env not in {AppEnvironment.LOCAL, AppEnvironment.CI, AppEnvironment.DEV}:
                raise ValueError("Platform bootstrap is prohibited in UAT/production")
            if not self.platform_bootstrap_login.strip():
                raise ValueError("Platform bootstrap login is required when bootstrap is enabled")
            if not self.platform_bootstrap_password:
                raise ValueError("Platform bootstrap password is required when bootstrap is enabled")
            if self.platform_admin_token_ttl_minutes is None:
                raise ValueError("Platform Admin token TTL is required when bootstrap is enabled")
        return self

    @property
    def clerk_authorized_party_list(self) -> list[str]:
        return [x.strip() for x in self.clerk_authorized_parties.split(",") if x.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
