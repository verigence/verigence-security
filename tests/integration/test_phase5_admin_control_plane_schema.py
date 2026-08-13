from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.services.admin_control_plane_catalog import (
    SECURITY_ADMIN_PERMISSION_KEYS,
    STANDARD_PLATFORM_ROLE_BUNDLES,
    STANDARD_TENANT_ADMIN_ROLES,
    StandardTenantAdminRoleSeeder,
)

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

EXPECTED_NEW_TABLES = frozenset(
    {
        "platform_roles",
        "platform_role_permissions",
        "platform_user_role_assignments",
        "local_user_credentials",
        "modules",
        "module_role_templates",
        "module_role_template_permissions",
        "role_template_bindings",
        "groups",
        "group_memberships",
        "group_role_assignments",
        "tenant_invitations",
        "privileged_access_requests",
        "admin_change_records",
        "security_control_definitions",
        "platform_security_control_settings",
        "tenant_security_control_overrides",
        "tenant_self_onboarding_settings",
        "self_onboarding_requests",
    }
)

EXPECTED_CONFIGURABLE_CONTROLS = frozenset(
    {
        "user_access.device_enforcement",
        "user_access.device_limit",
        "user_access.geo_enforcement",
        "user_access.geo_freshness",
        "user_access.geo_accuracy",
        "user_access.geo_integrity",
        "user_access.geo_radius",
        "user_access.schedule_enforcement",
        "user_access.network_risk_enforcement",
        "user_access.refresh_geo_revalidation",
        "admin.privileged_access_approval",
        "admin.self_onboarding",
    }
)

EXPECTED_CORE_CONTROLS = frozenset(
    {
        "core.identity_verification",
        "core.token_signature_validation",
        "core.token_issuer_audience_validation",
        "core.actor_type_validation",
        "core.principal_status_validation",
        "core.tenant_isolation",
        "core.tenant_membership_validation",
        "core.rbac_permission_enforcement",
        "core.token_expiry",
        "core.admin_audit",
        "core.onboarding_human_acceptance",
        "core.secret_hashing",
    }
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


def _create_user(conn: object, *, user_id: str, now: datetime) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.security_principals
            (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,'USER','Admin Control Plane test','ACTIVE',:now,:now)
            """
        ),
        {"user_id": user_id, "now": now},
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.users
            (user_id,display_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,'Admin Control Plane test','ACTIVE',:now,:now)
            """
        ),
        {"user_id": user_id, "now": now},
    )


def _create_tenant(conn: object, *, tenant_id: str, now: datetime) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.tenants
            (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
            VALUES (:tenant_id,:tenant_code,'Admin Control Plane test',
                    'CONFIGURING',:now,:now)
            """
        ),
        {"tenant_id": tenant_id, "tenant_code": f"v14-{tenant_id}", "now": now},
    )


def test_v14_schema_and_seed_catalogues_match_approved_design() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            new_tables = frozenset(
                str(value)
                for value in conn.execute(
                    text(
                        """
                        SELECT tablename
                        FROM pg_tables
                        WHERE schemaname='security'
                        """
                    )
                ).scalars()
                if str(value) in EXPECTED_NEW_TABLES
            )
            assert new_tables == EXPECTED_NEW_TABLES

            permission_keys = frozenset(
                str(value)
                for value in conn.execute(
                    text(
                        """
                        SELECT permission_key
                        FROM security.permissions
                        WHERE module_key='security' AND catalog_version='1.4'
                        """
                    )
                ).scalars()
            )
            assert permission_keys == SECURITY_ADMIN_PERMISSION_KEYS

            for role_key, expected_permissions in STANDARD_PLATFORM_ROLE_BUNDLES.items():
                actual_permissions = frozenset(
                    str(value)
                    for value in conn.execute(
                        text(
                            """
                            SELECT permission_key
                            FROM security.platform_role_permissions
                            WHERE role_key=:role_key
                            """
                        ),
                        {"role_key": role_key},
                    ).scalars()
                )
                assert actual_permissions == expected_permissions

            controls = {
                str(row["control_key"]): row
                for row in conn.execute(
                    text(
                        """
                        SELECT control_key,configurable,default_enabled
                        FROM security.security_control_definitions
                        WHERE status='ACTIVE'
                        """
                    )
                ).mappings()
            }
            assert frozenset(controls) == EXPECTED_CONFIGURABLE_CONTROLS | EXPECTED_CORE_CONTROLS
            assert all(bool(controls[key]["configurable"]) for key in EXPECTED_CONFIGURABLE_CONTROLS)
            assert all(not bool(controls[key]["configurable"]) for key in EXPECTED_CORE_CONTROLS)
            assert all(bool(controls[key]["default_enabled"]) for key in EXPECTED_CORE_CONTROLS)
            assert not bool(controls["admin.self_onboarding"]["default_enabled"])
    finally:
        engine.dispose()


def test_standard_tenant_admin_roles_seed_exactly_and_detect_drift() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            _create_tenant(conn, tenant_id=tenant_id, now=now)

        with Session(engine) as session:  # type: ignore[arg-type]
            seeder = StandardTenantAdminRoleSeeder(session)
            assert seeder.seed(tenant_id=tenant_id, now=now)
            assert seeder.seed(tenant_id=tenant_id, now=now)

        with engine.connect() as conn:
            role_rows = list(
                conn.execute(
                    text(
                        """
                        SELECT role_id,role_key
                        FROM security.roles
                        WHERE tenant_id=:tenant_id
                        """
                    ),
                    {"tenant_id": tenant_id},
                ).mappings()
            )
            assert {str(row["role_key"]) for row in role_rows} == {
                role.role_key for role in STANDARD_TENANT_ADMIN_ROLES
            }
            expected_by_key = {
                role.role_key: role.permission_keys for role in STANDARD_TENANT_ADMIN_ROLES
            }
            for row in role_rows:
                actual = frozenset(
                    str(value)
                    for value in conn.execute(
                        text(
                            """
                            SELECT permission_key
                            FROM security.role_permissions
                            WHERE tenant_id=:tenant_id AND role_id=:role_id
                            """
                        ),
                        {"tenant_id": tenant_id, "role_id": str(row["role_id"])},
                    ).scalars()
                )
                assert actual == expected_by_key[str(row["role_key"])]

        with engine.begin() as conn:
            auditor_role_id = conn.execute(
                text(
                    """
                    SELECT role_id FROM security.roles
                    WHERE tenant_id=:tenant_id AND role_key='tenant.auditor'
                    """
                ),
                {"tenant_id": tenant_id},
            ).scalar_one()
            conn.execute(
                text(
                    """
                    INSERT INTO security.role_permissions
                    (tenant_id,role_id,permission_key,assigned_at_utc)
                    VALUES (:tenant_id,:role_id,'security.tenant.create',:now)
                    """
                ),
                {"tenant_id": tenant_id, "role_id": auditor_role_id, "now": now},
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            with pytest.raises(RuntimeError, match="Reserved Tenant Admin role drift"):
                StandardTenantAdminRoleSeeder(session).seed(tenant_id=tenant_id, now=now)
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.role_permissions WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.roles WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
        engine.dispose()


def test_group_relationships_reject_cross_tenant_references() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    user_id = str(uuid4())
    group_id = str(uuid4())
    membership_id = str(uuid4())
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            _create_tenant(conn, tenant_id=tenant_a, now=now)
            _create_tenant(conn, tenant_id=tenant_b, now=now)
            _create_user(conn, user_id=user_id, now=now)
            conn.execute(
                text(
                    """
                    INSERT INTO security.groups
                    (group_id,tenant_id,group_key,group_name,status,created_by_user_id,
                     created_at_utc,updated_at_utc)
                    VALUES (:group_id,:tenant_id,'SALES','Sales','ACTIVE',:user_id,:now,:now)
                    """
                ),
                {
                    "group_id": group_id,
                    "tenant_id": tenant_a,
                    "user_id": user_id,
                    "now": now,
                },
            )

        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.group_memberships
                    (group_membership_id,tenant_id,group_id,user_id,status,
                     added_by_user_id,added_at_utc)
                    VALUES (:membership_id,:tenant_b,:group_id,:user_id,'ACTIVE',
                            :user_id,:now)
                    """
                ),
                {
                    "membership_id": membership_id,
                    "tenant_b": tenant_b,
                    "group_id": group_id,
                    "user_id": user_id,
                    "now": now,
                },
            )
    finally:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM security.groups WHERE group_id=:id"), {"id": group_id})
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id IN (:a,:b)"),
                {"a": tenant_a, "b": tenant_b},
            )
            conn.execute(text("DELETE FROM security.users WHERE user_id=:id"), {"id": user_id})
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": user_id},
            )
        engine.dispose()


def test_self_onboarding_schema_is_hash_only_and_duplicate_safe() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    user_id = str(uuid4())
    external_identity_id = str(uuid4())
    request_id = str(uuid4())
    duplicate_request_id = str(uuid4())
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            _create_tenant(conn, tenant_id=tenant_id, now=now)
            _create_user(conn, user_id=user_id, now=now)
            conn.execute(
                text(
                    """
                    INSERT INTO security.external_identities
                    (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                    VALUES (:external_identity_id,:user_id,'DEV_MOCK',:subject,'ACTIVE',:now)
                    """
                ),
                {
                    "external_identity_id": external_identity_id,
                    "user_id": user_id,
                    "subject": f"self-onboarding-{user_id}",
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenant_self_onboarding_settings
                    (tenant_id,token_hash,token_version,status,created_by_user_id,
                     created_at_utc,updated_by_user_id,updated_at_utc)
                    VALUES (:tenant_id,'argon2id-test-hash',1,'ACTIVE',:user_id,
                            :now,:user_id,:now)
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.self_onboarding_requests
                    (self_onboarding_request_id,tenant_id,user_id,external_identity_id,
                     status,submitted_at_utc,submitted_source_ip,correlation_id)
                    VALUES (:request_id,:tenant_id,:user_id,:external_identity_id,
                            'PENDING_ADMIN_APPROVAL',:now,'203.0.113.10',:correlation_id)
                    """
                ),
                {
                    "request_id": request_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "external_identity_id": external_identity_id,
                    "now": now,
                    "correlation_id": f"self-{request_id}",
                },
            )

        with engine.connect() as conn:
            columns = frozenset(
                str(value)
                for value in conn.execute(
                    text(
                        """
                        SELECT column_name FROM information_schema.columns
                        WHERE table_schema='security'
                          AND table_name='tenant_self_onboarding_settings'
                        """
                    )
                ).scalars()
            )
            assert "token_hash" in columns
            assert "token" not in columns
            assert "raw_token" not in columns

        with pytest.raises(IntegrityError), engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.self_onboarding_requests
                    (self_onboarding_request_id,tenant_id,user_id,external_identity_id,
                     status,submitted_at_utc,submitted_source_ip,correlation_id)
                    VALUES (:request_id,:tenant_id,:user_id,:external_identity_id,
                            'PENDING_ADMIN_APPROVAL',:now,'203.0.113.11',:correlation_id)
                    """
                ),
                {
                    "request_id": duplicate_request_id,
                    "tenant_id": tenant_id,
                    "user_id": user_id,
                    "external_identity_id": external_identity_id,
                    "now": now,
                    "correlation_id": f"duplicate-{duplicate_request_id}",
                },
            )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.self_onboarding_requests WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_self_onboarding_settings WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.external_identities WHERE user_id=:id"),
                {"id": user_id},
            )
            conn.execute(text("DELETE FROM security.users WHERE user_id=:id"), {"id": user_id})
            conn.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                {"id": user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()
