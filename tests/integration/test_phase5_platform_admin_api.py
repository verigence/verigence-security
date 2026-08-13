from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.api.dependencies import get_settings as dependency_settings
from verigence_security.config import Settings, get_settings
from verigence_security.main import app
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.services.admin_control_plane_catalog import STANDARD_TENANT_ADMIN_ROLES

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


def _test_settings(database_url: str) -> Settings:
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
        app_env="ci",
        database_url=database_url,
        security_key_id="platform-test-key",
        security_private_key_pem=private_pem,
        security_public_key_pem=public_pem,
        platform_admin_token_ttl_minutes=10,
        network_risk_mode="disabled",
    )


def test_platform_admin_login_password_change_and_direct_tenant_api() -> None:
    assert TEST_DATABASE_URL is not None
    database_url = _sqlalchemy_url(TEST_DATABASE_URL)
    engine = create_engine(database_url, pool_pre_ping=True)
    settings = _test_settings(database_url)
    login_name = f"platform-test-{uuid4()}"
    initial_password = f"initial-{uuid4()}"
    replacement_password = f"replacement-{uuid4()}"
    onboarding_token = f"onboarding-{uuid4()}"
    tenant_code = f"API-{uuid4()}"[:80]
    admin_user_id: str | None = None
    tenant_id: str | None = None

    try:
        with Session(engine) as session:  # type: ignore[arg-type]
            repository = PlatformAdminRepository(session)
            admin_user_id = repository.create_bootstrap_super_admin(
                login_name=login_name,
                password_hash=PasswordHasher().hash(initial_password),
                now=datetime.now(UTC),
            )
            repository.commit()

        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[dependency_settings] = lambda: settings
        with TestClient(app) as client:
            login = client.post(
                "/security/v1/platform/auth/login",
                json={"loginName": login_name, "password": initial_password},
            )
            assert login.status_code == 200
            initial = login.json()
            assert initial["mustChangePassword"] is True
            assert initial["roles"] == ["platform.super_admin"]
            assert "security.tenant.create" in initial["permissions"]

            blocked_create = client.post(
                "/security/v1/platform/tenants",
                headers={"Authorization": f"Bearer {initial['accessToken']}"},
                json={"tenantCode": tenant_code, "tenantName": "Blocked before password change"},
            )
            assert blocked_create.status_code == 403
            assert blocked_create.json()["code"] == "PERMISSION_DENIED"

            changed = client.post(
                "/security/v1/platform/auth/change-password",
                headers={"Authorization": f"Bearer {initial['accessToken']}"},
                json={"newPassword": replacement_password},
            )
            assert changed.status_code == 204

            relogin = client.post(
                "/security/v1/platform/auth/login",
                json={"loginName": login_name, "password": replacement_password},
            )
            assert relogin.status_code == 200
            current = relogin.json()
            assert current["mustChangePassword"] is False
            token = current["accessToken"]

            me = client.get(
                "/security/v1/platform/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert me.status_code == 200
            assert me.json()["userId"] == admin_user_id
            assert me.json()["mustChangePassword"] is False

            created = client.post(
                "/security/v1/platform/tenants",
                headers={"Authorization": f"Bearer {token}"},
                json={
                    "tenantCode": tenant_code,
                    "tenantName": "Platform API Tenant",
                    "selfOnboarding": {"enabled": True, "token": onboarding_token},
                },
            )
            assert created.status_code == 201
            created_body = created.json()
            tenant_id = created_body["tenantId"]
            assert created_body["status"] == "CONFIGURING"

            fetched = client.get(
                f"/security/v1/platform/tenants/{tenant_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert fetched.status_code == 200
            assert fetched.json()["tenantCode"] == tenant_code

            listed = client.get(
                "/security/v1/platform/tenants",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert listed.status_code == 200
            assert any(row["tenantId"] == tenant_id for row in listed.json())

            updated = client.patch(
                f"/security/v1/platform/tenants/{tenant_id}",
                headers={"Authorization": f"Bearer {token}"},
                json={"tenantName": "Renamed Platform API Tenant"},
            )
            assert updated.status_code == 200
            assert updated.json()["tenantName"] == "Renamed Platform API Tenant"
            assert updated.json()["status"] == "CONFIGURING"

        assert tenant_id is not None
        with engine.connect() as conn:
            roles = frozenset(
                str(value)
                for value in conn.execute(
                    text(
                        """
                        SELECT role_key FROM security.roles
                        WHERE tenant_id=:tenant_id
                        """
                    ),
                    {"tenant_id": tenant_id},
                ).scalars()
            )
            assert roles == {role.role_key for role in STANDARD_TENANT_ADMIN_ROLES}

            onboarding = conn.execute(
                text(
                    """
                    SELECT token_hash,status,token_version
                    FROM security.tenant_self_onboarding_settings
                    WHERE tenant_id=:tenant_id
                    """
                ),
                {"tenant_id": tenant_id},
            ).mappings().one()
            assert onboarding["status"] == "ACTIVE"
            assert onboarding["token_version"] == 1
            assert onboarding["token_hash"] != onboarding_token
            assert PasswordHasher().verify(str(onboarding["token_hash"]), onboarding_token)

            operations = frozenset(
                str(value)
                for value in conn.execute(
                    text(
                        """
                        SELECT operation_key FROM security.admin_change_records
                        WHERE actor_user_id=:user_id
                        """
                    ),
                    {"user_id": admin_user_id},
                ).scalars()
            )
            assert {
                "platform.auth.change_password",
                "platform.tenant.create",
                "platform.tenant.update",
            }.issubset(operations)
    finally:
        app.dependency_overrides.clear()
        if admin_user_id is not None:
            with engine.begin() as conn:
                conn.execute(
                    text("DELETE FROM security.admin_change_records WHERE actor_user_id=:id"),
                    {"id": admin_user_id},
                )
                if tenant_id is not None:
                    conn.execute(
                        text(
                            "DELETE FROM security.tenant_self_onboarding_settings "
                            "WHERE tenant_id=:id"
                        ),
                        {"id": tenant_id},
                    )
                    conn.execute(
                        text("DELETE FROM security.role_permissions WHERE tenant_id=:id"),
                        {"id": tenant_id},
                    )
                    conn.execute(
                        text("DELETE FROM security.roles WHERE tenant_id=:id"),
                        {"id": tenant_id},
                    )
                    conn.execute(
                        text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                        {"id": tenant_id},
                    )
                conn.execute(
                    text(
                        "DELETE FROM security.platform_user_role_assignments "
                        "WHERE user_id=:id"
                    ),
                    {"id": admin_user_id},
                )
                conn.execute(
                    text("DELETE FROM security.local_user_credentials WHERE user_id=:id"),
                    {"id": admin_user_id},
                )
                conn.execute(
                    text("DELETE FROM security.users WHERE user_id=:id"),
                    {"id": admin_user_id},
                )
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                    {"id": admin_user_id},
                )
        engine.dispose()
