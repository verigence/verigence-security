from __future__ import annotations

from dataclasses import dataclass, field

from argon2 import PasswordHasher

from verigence_security.config import Settings
from verigence_security.services import platform_admin as platform_admin_module
from verigence_security.services.platform_admin import PlatformBootstrapService


@dataclass
class FakePlatformAdminRepository:
    has_super_admin: bool = False
    created_password_hash: str | None = None
    created_login: str | None = None
    commits: int = 0
    rollbacks: int = 0
    audit_operations: list[str] = field(default_factory=list)

    def active_super_admin_exists(self) -> bool:
        return self.has_super_admin

    def create_bootstrap_super_admin(
        self,
        *,
        login_name: str,
        password_hash: str,
        now: object,
    ) -> str:
        _ = now
        self.created_login = login_name
        self.created_password_hash = password_hash
        self.has_super_admin = True
        return "00000000-0000-0000-0000-000000000001"

    def insert_admin_change(self, **values: object) -> None:
        self.audit_operations.append(str(values["operation_key"]))

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1


def test_bootstrap_hashes_secret_and_does_not_reset_existing_admin(monkeypatch: object) -> None:
    fake = FakePlatformAdminRepository()
    monkeypatch.setattr(  # type: ignore[attr-defined]
        platform_admin_module,
        "PlatformAdminRepository",
        lambda _session: fake,
    )
    bootstrap_password = "integration-bootstrap-secret"
    settings = Settings(
        app_env="ci",
        platform_bootstrap_enabled=True,
        platform_bootstrap_login="configured-super-admin",
        platform_bootstrap_password=bootstrap_password,
        platform_admin_token_ttl_minutes=10,
        network_risk_mode="disabled",
    )

    service = PlatformBootstrapService(object(), settings)  # type: ignore[arg-type]
    created = service.bootstrap_if_needed()
    assert created == "00000000-0000-0000-0000-000000000001"
    assert fake.created_login == "configured-super-admin"
    assert fake.created_password_hash is not None
    assert fake.created_password_hash != bootstrap_password
    assert PasswordHasher().verify(fake.created_password_hash, bootstrap_password)
    assert fake.audit_operations == ["platform.super_admin.bootstrap"]
    assert fake.commits == 1

    assert service.bootstrap_if_needed() is None
    assert fake.commits == 1
    assert fake.created_password_hash is not None
