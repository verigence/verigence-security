from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.repositories.admin_repository import SecurityAdminRepository
from verigence_security.repositories.security_repository import SecurityRepository
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


@pytest.fixture()
def admin_fixture() -> tuple[object, str, str]:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    now = datetime.now(UTC)

    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,'Phase 5 Tenant','CONFIGURING',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "tenant_code": f"p5-{tenant_id}",
                "now": now,
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER','Phase 5 Administrator','ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'Phase 5 Administrator','ACTIVE',:now,:now)
                """
            ),
            {"user_id": user_id, "now": now},
        )

    try:
        yield engine, tenant_id, user_id
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
                text("DELETE FROM security.users WHERE user_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()


def _security_policy(*, version: int, status: str) -> TenantSecurityPolicyConfiguration:
    return TenantSecurityPolicyConfiguration(
        max_active_devices_per_user=3,
        max_geo_accuracy_meters=75.5,
        max_geo_age_seconds=240,
        geo_revalidation_interval_seconds=180,
        access_token_ttl_minutes=12,
        machine_token_ttl_minutes=8,
        session_idle_timeout_minutes=25,
        session_max_duration_minutes=90,
        vpn_detected_action="DENY",
        vpn_unknown_action="FLAG",
        configuration_version=version,
        status=status,
    )


def test_security_policy_upsert_preserves_explicit_values_and_runtime_compatibility(
    admin_fixture: tuple[object, str, str],
) -> None:
    engine, tenant_id, user_id = admin_fixture
    now = datetime.now(UTC)

    with Session(engine) as session:  # type: ignore[arg-type]
        repository = SecurityAdminRepository(session)
        service = TenantConfigurationService(repository)
        assert service.configure_security_policy(
            tenant_id=tenant_id,
            configuration=_security_policy(version=1, status="DRAFT"),
            updated_by_user_id=user_id,
            updated_at=now,
        )
        snapshot = service.snapshot(tenant_id)
        assert snapshot is not None
        assert snapshot.tenant_status == "CONFIGURING"
        assert snapshot.security_policy_status == "DRAFT"

        assert service.configure_security_policy(
            tenant_id=tenant_id,
            configuration=_security_policy(version=2, status="ACTIVE"),
            updated_by_user_id=user_id,
            updated_at=now,
        )

    with Session(engine) as session:  # type: ignore[arg-type]
        runtime = SecurityRepository(session).get_tenant_policy(tenant_id)
        assert runtime.max_active_devices_per_user == 3
        assert runtime.max_geo_accuracy_meters == 75.5
        assert runtime.max_geo_age_seconds == 240
        assert runtime.geo_revalidation_interval_seconds == 180
        assert runtime.access_token_ttl_minutes == 12
        assert runtime.machine_token_ttl_minutes == 8
        assert runtime.session_idle_timeout_minutes == 25
        assert runtime.session_max_duration_minutes == 90
        assert runtime.vpn_detected_action == "DENY"
        assert runtime.vpn_unknown_action == "FLAG"
        assert runtime.status == "ACTIVE"

    with engine.connect() as conn:  # type: ignore[union-attr]
        row = conn.execute(
            text(
                """
                SELECT configuration_version,count(*) OVER () AS policy_count
                FROM security.tenant_security_policies
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().one()
    assert row["configuration_version"] == 2
    assert row["policy_count"] == 1


def test_retention_policy_upsert_preserves_explicit_days(
    admin_fixture: tuple[object, str, str],
) -> None:
    engine, tenant_id, user_id = admin_fixture
    now = datetime.now(UTC)

    with Session(engine) as session:  # type: ignore[arg-type]
        service = TenantConfigurationService(SecurityAdminRepository(session))
        assert service.configure_retention_policy(
            tenant_id=tenant_id,
            configuration=SecurityRetentionPolicyConfiguration(
                access_context_retention_days=31,
                access_session_retention_days=47,
                security_event_retention_days=61,
                status="ACTIVE",
            ),
            updated_by_user_id=user_id,
            updated_at=now,
        )
        snapshot = service.snapshot(tenant_id)
        assert snapshot is not None
        assert snapshot.retention_policy_status == "ACTIVE"

    with engine.connect() as conn:  # type: ignore[union-attr]
        row = conn.execute(
            text(
                """
                SELECT access_context_retention_days,access_session_retention_days,
                       security_event_retention_days,status
                FROM security.security_retention_policies
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().one()
    assert row["access_context_retention_days"] == 31
    assert row["access_session_retention_days"] == 47
    assert row["security_event_retention_days"] == 61
    assert row["status"] == "ACTIVE"


def test_database_constraints_reject_invalid_admin_configuration(
    admin_fixture: tuple[object, str, str],
) -> None:
    engine, tenant_id, user_id = admin_fixture
    now = datetime.now(UTC)

    with Session(engine) as session:  # type: ignore[arg-type]
        service = TenantConfigurationService(SecurityAdminRepository(session))
        with pytest.raises(IntegrityError):
            service.configure_retention_policy(
                tenant_id=tenant_id,
                configuration=SecurityRetentionPolicyConfiguration(
                    access_context_retention_days=0,
                    access_session_retention_days=30,
                    security_event_retention_days=30,
                    status="ACTIVE",
                ),
                updated_by_user_id=user_id,
                updated_at=now,
            )

    with engine.connect() as conn:  # type: ignore[union-attr]
        count = conn.execute(
            text(
                "SELECT count(*) FROM security.security_retention_policies "
                "WHERE tenant_id=:tenant_id"
            ),
            {"tenant_id": tenant_id},
        ).scalar_one()
    assert count == 0
