from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from verigence_security.api.dependencies import get_settings as dependency_settings
from verigence_security.config import Settings, get_settings
from verigence_security.main import app
from verigence_security.services.admin_control_plane_catalog import STANDARD_TENANT_ADMIN_ROLES

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

CLERK_ISSUER = "https://clerk.integration.test"
CLERK_AZP = "https://security-integration.test"
CLERK_SUPER_ADMIN_SUBJECT = "user_clerk_platform_super_admin_test"


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


def _rsa_pems() -> tuple[str, str]:
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
    return private_pem, public_pem


def _test_settings(database_url: str, clerk_public_pem: str) -> Settings:
    security_private_pem, security_public_pem = _rsa_pems()
    return Settings(
        app_env="ci",
        database_url=database_url,
        clerk_issuer=CLERK_ISSUER,
        clerk_jwt_key=clerk_public_pem,
        clerk_authorized_parties=CLERK_AZP,
        security_bootstrap_enabled=True,
        security_bootstrap_super_admin_clerk_user_id=CLERK_SUPER_ADMIN_SUBJECT,
        security_key_id="platform-test-key",
        security_private_key_pem=security_private_pem,
        security_public_key_pem=security_public_pem,
        platform_admin_token_ttl_minutes=10,
        network_risk_mode="disabled",
    )


def _clerk_token(private_pem: str, subject: str) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "iss": CLERK_ISSUER,
            "sub": subject,
            "sid": f"sess_{uuid4()}",
            "azp": CLERK_AZP,
            "iat": now,
            "exp": now + timedelta(minutes=10),
        },
        private_pem,
        algorithm="RS256",
    )


def test_clerk_bootstrap_platform_login_and_direct_tenant_api() -> None:
    assert TEST_DATABASE_URL is not None
    database_url = _sqlalchemy_url(TEST_DATABASE_URL)
    engine = create_engine(database_url, pool_pre_ping=True)
    clerk_private_pem, clerk_public_pem = _rsa_pems()
    settings = _test_settings(database_url, clerk_public_pem)
    clerk_token = _clerk_token(clerk_private_pem, CLERK_SUPER_ADMIN_SUBJECT)
    wrong_clerk_token = _clerk_token(clerk_private_pem, "user_wrong_bootstrap_subject")
    admin_user_id: str | None = None
    tenant_id: str | None = None

    try:
        app.dependency_overrides[get_settings] = lambda: settings
        app.dependency_overrides[dependency_settings] = lambda: settings
        with TestClient(app) as client:
            local_password_login = client.post(
                "/security/v1/platform/auth/login",
                json={"loginName": "legacy-user", "password": "legacy-password"},
            )
            assert local_password_login.status_code == 401
            assert local_password_login.json()["code"] == "AUTH_TOKEN_INVALID"

            wrong_claim = client.post(
                "/security/v1/platform/bootstrap/claim",
                headers={"Authorization": f"Bearer {wrong_clerk_token}"},
            )
            assert wrong_claim.status_code == 403
            assert wrong_claim.json()["code"] == "PERMISSION_DENIED"

            claim = client.post(
                "/security/v1/platform/bootstrap/claim",
                headers={"Authorization": f"Bearer {clerk_token}"},
            )
            assert claim.status_code == 200
            claimed = claim.json()
            admin_user_id = claimed["userId"]
            assert claimed["mustChangePassword"] is False
            assert claimed["roles"] == ["platform.super_admin"]
            assert "security.tenant.create" in claimed["permissions"]

            second_claim = client.post(
                "/security/v1/platform/bootstrap/claim",
                headers={"Authorization": f"Bearer {clerk_token}"},
            )
            assert second_claim.status_code == 403
            assert second_claim.json()["code"] == "PERMISSION_DENIED"

            login = client.post(
                "/security/v1/platform/auth/login",
                headers={"Authorization": f"Bearer {clerk_token}"},
            )
            assert login.status_code == 200
            current = login.json()
            assert current["userId"] == admin_user_id
            assert current["mustChangePassword"] is False
            platform_token = current["accessToken"]

            me = client.get(
                "/security/v1/platform/me",
                headers={"Authorization": f"Bearer {platform_token}"},
            )
            assert me.status_code == 200
            assert me.json()["userId"] == admin_user_id
            assert me.json()["mustChangePassword"] is False

            created = client.post(
                "/security/v1/platform/tenants",
                headers={
                    "Authorization": f"Bearer {platform_token}",
                    "Idempotency-Key": f"platform-api-{uuid4()}",
                },
                json={"tenantName": "Platform API Tenant"},
            )
            assert created.status_code == 201
            created_body = created.json()
            tenant_id = created_body["tenantId"]
            tenant_code = created_body["tenantCode"]
            assert tenant_code.startswith("tenant-")
            assert len(tenant_code) == 39
            assert created_body["status"] == "CONFIGURING"

            fetched = client.get(
                f"/security/v1/platform/tenants/{tenant_id}",
                headers={"Authorization": f"Bearer {platform_token}"},
            )
            assert fetched.status_code == 200
            assert fetched.json()["tenantCode"] == tenant_code

            listed = client.get(
                "/security/v1/platform/tenants",
                headers={"Authorization": f"Bearer {platform_token}"},
            )
            assert listed.status_code == 200
            assert any(row["tenantId"] == tenant_id for row in listed.json())

            updated = client.patch(
                f"/security/v1/platform/tenants/{tenant_id}",
                headers={"Authorization": f"Bearer {platform_token}"},
                json={"tenantName": "Renamed Platform API Tenant"},
            )
            assert updated.status_code == 200
            assert updated.json()["tenantName"] == "Renamed Platform API Tenant"

        assert admin_user_id is not None
        assert tenant_id is not None
        with engine.connect() as conn:
            identity = conn.execute(
                text(
                    """
                    SELECT provider,provider_subject,status
                    FROM security.external_identities
                    WHERE user_id=:user_id
                    """
                ),
                {"user_id": admin_user_id},
            ).mappings().one()
            assert identity["provider"] == "CLERK"
            assert identity["provider_subject"] == CLERK_SUPER_ADMIN_SUBJECT
            assert identity["status"] == "ACTIVE"

            local_credential = conn.execute(
                text(
                    """
                    SELECT 1 FROM security.local_user_credentials
                    WHERE user_id=:user_id
                    """
                ),
                {"user_id": admin_user_id},
            ).first()
            assert local_credential is None

            roles = frozenset(
                str(value)
                for value in conn.execute(
                    text("SELECT role_key FROM security.roles WHERE tenant_id=:tenant_id"),
                    {"tenant_id": tenant_id},
                ).scalars()
            )
            assert roles == {role.role_key for role in STANDARD_TENANT_ADMIN_ROLES}

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
                "platform.super_admin.clerk_bootstrap",
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
                            """
                            DELETE FROM security.tenant_role_permissions
                            WHERE tenant_id=:id
                            """
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
                        """
                        DELETE FROM security.platform_user_role_assignments
                        WHERE user_id=:id
                        """
                    ),
                    {"id": admin_user_id},
                )
                conn.execute(
                    text("DELETE FROM security.external_identities WHERE user_id=:id"),
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
