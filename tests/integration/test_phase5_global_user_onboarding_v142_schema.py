from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, text

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(value: str) -> str:
    if value.startswith("postgresql+psycopg://"):
        return value
    if value.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql+asyncpg://")
    if value.startswith("postgresql://"):
        return "postgresql+psycopg://" + value.removeprefix("postgresql://")
    if value.startswith("postgres://"):
        return "postgresql+psycopg://" + value.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be PostgreSQL")


def test_v142_schema_and_control_registry_state() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            tables = set(
                conn.execute(
                    text(
                        """
                        SELECT tablename FROM pg_tables
                        WHERE schemaname='security'
                        """
                    )
                ).scalars()
            )
            assert "platform_user_onboarding_settings" in tables
            assert "platform_user_onboarding_requests" in tables
            assert "user_tenant_authorization_state" in tables

            permissions = set(
                conn.execute(
                    text(
                        """
                        SELECT permission_key FROM security.permissions
                        WHERE catalog_version='1.4.2'
                        """
                    )
                ).scalars()
            )
            assert permissions == {
                "security.user.read",
                "security.user.manage",
                "security.user_onboarding.read",
                "security.user_onboarding.manage",
            }

            super_admin_permissions = set(
                conn.execute(
                    text(
                        """
                        SELECT permission_key FROM security.platform_role_permissions
                        WHERE role_key='platform.super_admin'
                        """
                    )
                ).scalars()
            )
            assert permissions <= super_admin_permissions

            controls = {
                str(row["control_key"]): str(row["status"])
                for row in conn.execute(
                    text(
                        """
                        SELECT control_key,status FROM security.security_control_definitions
                        WHERE control_key IN (
                          'admin.self_onboarding',
                          'core.tenant_membership_validation',
                          'admin.global_user_onboarding',
                          'core.user_status_validation',
                          'core.tenant_authorization_state'
                        )
                        """
                    )
                ).mappings()
            }
            assert controls["admin.self_onboarding"] == "RETIRED"
            assert controls["core.tenant_membership_validation"] == "RETIRED"
            assert controls["admin.global_user_onboarding"] == "ACTIVE"
            assert controls["core.user_status_validation"] == "ACTIVE"
            assert controls["core.tenant_authorization_state"] == "ACTIVE"

            outcome_type = conn.execute(
                text(
                    """
                    SELECT character_maximum_length
                    FROM information_schema.columns
                    WHERE table_schema='security'
                      AND table_name='security_events'
                      AND column_name='outcome'
                    """
                )
            ).scalar_one()
            assert int(outcome_type) >= 40
    finally:
        engine.dispose()
