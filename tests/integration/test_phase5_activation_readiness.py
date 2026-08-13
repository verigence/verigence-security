from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.admin_repository import SecurityAdminRepository
from verigence_security.services.tenant_activation_readiness import (
    TenantActivationReadinessService,
)
from verigence_security.services.tenant_configuration import (
    SecurityRetentionPolicyConfiguration,
    TenantConfigurationService,
    TenantSecurityPolicyConfiguration,
)

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


def _security_policy() -> TenantSecurityPolicyConfiguration:
    return TenantSecurityPolicyConfiguration(
        max_active_devices_per_user=2,
        max_geo_accuracy_meters=100,
        max_geo_age_seconds=300,
        geo_revalidation_interval_seconds=300,
        access_token_ttl_minutes=10,
        machine_token_ttl_minutes=10,
        session_idle_timeout_minutes=30,
        session_max_duration_minutes=60,
        vpn_detected_action="DENY",
        vpn_unknown_action="FLAG",
        configuration_version=1,
        status="ACTIVE",
    )


def test_readiness_reports_known_prerequisites_but_stays_fail_closed() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    admin_user_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 5 Readiness',
                            'CONFIGURING',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p5-ready-{tenant_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,
                     created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','Phase 5 Readiness Admin','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": admin_user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'Phase 5 Readiness Admin','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": admin_user_id, "now": now},
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            readiness = TenantActivationReadinessService(SecurityAdminRepository(session))
            initial = readiness.evaluate(tenant_id)
            assert initial is not None
            assert initial.tenant_status == "CONFIGURING"
            assert not initial.known_prerequisites_pass
            assert not initial.prerequisite_catalogue_complete
            assert not initial.activation_allowed
            assert [item.key for item in initial.prerequisites] == [
                "SECURITY_POLICY_ACTIVE",
                "SECURITY_RETENTION_POLICY_ACTIVE",
            ]
            assert [item.passed for item in initial.prerequisites] == [False, False]

        with Session(engine) as session:  # type: ignore[arg-type]
            configuration = TenantConfigurationService(SecurityAdminRepository(session))
            assert configuration.configure_security_policy(
                tenant_id=tenant_id,
                configuration=_security_policy(),
                updated_by_user_id=admin_user_id,
                updated_at=now,
            )
            assert configuration.configure_retention_policy(
                tenant_id=tenant_id,
                configuration=SecurityRetentionPolicyConfiguration(
                    access_context_retention_days=30,
                    access_session_retention_days=30,
                    security_event_retention_days=30,
                    status="ACTIVE",
                ),
                updated_by_user_id=admin_user_id,
                updated_at=now,
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            readiness = TenantActivationReadinessService(SecurityAdminRepository(session))
            result = readiness.evaluate(tenant_id)
            assert result is not None
            assert result.known_prerequisites_pass
            assert not result.prerequisite_catalogue_complete
            assert not result.activation_allowed
            assert all(item.passed for item in result.prerequisites)

        with engine.connect() as conn:
            tenant_status = conn.execute(
                text("SELECT status FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).scalar_one()
        assert tenant_status == "CONFIGURING"
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.security_retention_policies WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_security_policies WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id"),
                {"user_id": admin_user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                {"user_id": admin_user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
        engine.dispose()
