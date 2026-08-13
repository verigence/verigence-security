from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.config import Settings
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.services.platform_admin import PlatformAdminService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _sqlalchemy_url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be a PostgreSQL URL")


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
        security_key_id="phase5-platform-admin-test",
        security_private_key_pem=private_pem,
        security_public_key_pem=public_pem,
    )


def test_platform_admin_auth_and_tenant_creation_on_neon() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    admin_id = str(uuid4())
    username = f"phase5-admin-{admin_id}"
    tenant_code = f"phase5-{uuid4()}"
    password = "Neon-Test-Password1!"
    now = datetime.now(UTC)

    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO security.platform_admins
                    (admin_id,username,display_name,password_hash,status,must_change_password,
                     created_at_utc,updated_at_utc)
                    VALUES (:admin_id,:username,'Phase 5 Platform Admin',:password_hash,
                            'ACTIVE',true,:now,:now)
                    """
                ),
                {
                    "admin_id": admin_id,
                    "username": username,
                    "password_hash": PasswordHasher().hash(password),
                    "now": now,
                },
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            service = PlatformAdminService(PlatformAdminRepository(session), _settings())
            login = service.login(username=username, password=password, now=now)
            claims = service.tokens.verify(login["access_token"])
            assert claims["sub"] == admin_id
            assert claims["admin_role"] == "SUPER_ADMIN"

            tenant = service.create_tenant(
                tenant_code=tenant_code,
                tenant_name="Phase 5 Platform Admin Tenant",
                now=now,
            )
            assert tenant["status"] == "CONFIGURING"

        with engine.connect() as connection:
            stored = connection.execute(
                text(
                    """
                    SELECT tenant_code,tenant_name,status
                    FROM security.tenants
                    WHERE tenant_id=:tenant_id
                    """
                ),
                {"tenant_id": tenant["tenant_id"]},
            ).mappings().one()
        assert stored["tenant_code"] == tenant_code
        assert stored["status"] == "CONFIGURING"
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM security.tenants WHERE tenant_code=:tenant_code"),
                {"tenant_code": tenant_code},
            )
            connection.execute(
                text("DELETE FROM security.platform_admins WHERE admin_id=:admin_id"),
                {"admin_id": admin_id},
            )
        engine.dispose()
