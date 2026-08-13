from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from verigence_security.config import Settings
from verigence_security.services.platform_admin import PlatformAdminService


class FakePlatformAdminRepository:
    def __init__(self) -> None:
        self.admin: dict[str, Any] | None = None
        self.tenant_rows: list[dict[str, Any]] = []
        self.commits = 0
        self.rollbacks = 0
        self.bootstrap_locks = 0

    def lock_bootstrap(self) -> None:
        self.bootstrap_locks += 1

    def admin_count(self) -> int:
        return 1 if self.admin else 0

    def admin_by_username(self, username: str) -> dict[str, Any] | None:
        if self.admin and self.admin["username"] == username:
            return self.admin
        return None

    def create_admin(self, **values: Any) -> None:
        self.admin = {
            **values,
            "status": "ACTIVE",
            "must_change_password": True,
        }

    def mark_login(self, *, admin_id: str, now: datetime) -> None:
        assert self.admin is not None
        assert self.admin["admin_id"] == admin_id
        self.admin["last_login_at_utc"] = now

    def create_tenant(self, **values: Any) -> None:
        self.tenant_rows.append({**values, "status": "CONFIGURING"})

    def tenants(self) -> list[dict[str, Any]]:
        return list(self.tenant_rows)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def _settings() -> Settings:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return Settings(
        app_env="dev",
        security_key_id="admin-test-key",
        security_private_key_pem=private_pem,
        security_public_key_pem=public_pem,
    )


def test_bootstrap_hashes_password_then_login_issues_platform_admin_token() -> None:
    repository = FakePlatformAdminRepository()
    service = PlatformAdminService(repository, _settings())  # type: ignore[arg-type]
    now = datetime.now(UTC)
    password = "UnitTest-Only-Password1!"

    admin = service.bootstrap(
        username="SuperAdmin",
        display_name="Platform Super Admin",
        password=password,
        now=now,
    )

    assert repository.bootstrap_locks == 1
    assert repository.admin is not None
    assert repository.admin["password_hash"] != password
    assert admin["username"] == "superadmin"
    assert admin["must_change_password"] is True

    login = service.login(username="superadmin", password=password, now=now)
    claims = service.tokens.verify(login["access_token"])

    assert login["role"] == "SUPER_ADMIN"
    assert claims["token_type"] == "PLATFORM_ADMIN"
    assert claims["admin_role"] == "SUPER_ADMIN"
    assert claims["username"] == "superadmin"


def test_super_admin_creates_tenant_in_configuring_state() -> None:
    repository = FakePlatformAdminRepository()
    service = PlatformAdminService(repository, _settings())  # type: ignore[arg-type]

    result = service.create_tenant(
        tenant_code="ABC-Motors",
        tenant_name="ABC Motors",
        now=datetime.now(UTC),
    )

    assert result["tenant_code"] == "abc-motors"
    assert result["status"] == "CONFIGURING"
    assert repository.tenant_rows[0]["status"] == "CONFIGURING"
