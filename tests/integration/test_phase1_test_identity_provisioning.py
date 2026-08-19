from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

import verigence_security.services.phase1_test_identity as test_identity_module
from verigence_security.services.phase1_test_identity import Phase1TestIdentityProvisioningService

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


def test_phase1_test_identity_is_canonical_idempotent_and_pc_equivalent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    conn = engine.connect()
    outer = conn.begin()
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    now = datetime.now(UTC)
    suffix = uuid4().hex
    test_subject = f"user_test_{suffix}"
    tenant_code = f"test-tenant-{suffix}"
    tenant_name = f"TestTenant-{suffix}"
    try:
        # Keep any real canonical singleton untouched outside this rolled-back test transaction.
        conn.execute(text("DELETE FROM security.phase1_test_identity"))

        admin = conn.execute(
            text(
                """
                SELECT a.user_id,e.provider_subject
                FROM security.user_admin_role_assignments a
                JOIN security.external_identities e
                  ON e.user_id=a.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                JOIN security.users u ON u.user_id=a.user_id AND u.status='ACTIVE'
                JOIN security.security_principals p
                  ON p.principal_id=a.user_id AND p.status='ACTIVE'
                WHERE a.role_key='SuperAdmin' AND a.scope_type='PLATFORM'
                  AND a.scope_id IS NULL AND a.status='ACTIVE'
                LIMIT 1
                """
            )
        ).mappings().first()
        if admin is None:
            admin_user_id = str(uuid4())
            admin_subject = f"user_admin_{suffix}"
            conn.execute(
                text(
                    """
                    INSERT INTO security.security_principals
                    (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'USER','test-admin','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": admin_user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.users
                    (user_id,display_name,status,created_at_utc,updated_at_utc)
                    VALUES (:user_id,'test-admin','ACTIVE',:now,:now)
                    """
                ),
                {"user_id": admin_user_id, "now": now},
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.external_identities
                    (external_identity_id,user_id,provider,provider_subject,status,linked_at_utc)
                    VALUES (:identity_id,:user_id,'CLERK',:subject,'ACTIVE',:now)
                    """
                ),
                {
                    "identity_id": str(uuid4()),
                    "user_id": admin_user_id,
                    "subject": admin_subject,
                    "now": now,
                },
            )
            conn.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:assignment_id,:user_id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',NULL,:now)
                    """
                ),
                {"assignment_id": str(uuid4()), "user_id": admin_user_id, "now": now},
            )
        else:
            admin_subject = str(admin["provider_subject"])

        monkeypatch.setattr(test_identity_module, "PHASE1_SUPER_ADMIN_CLERK_USER_ID", admin_subject)
        monkeypatch.setattr(test_identity_module, "PHASE1_TEST_USER_CLERK_USER_ID", test_subject)
        monkeypatch.setattr(test_identity_module, "PHASE1_TEST_TENANT_CODE", tenant_code)
        monkeypatch.setattr(test_identity_module, "PHASE1_TEST_TENANT_NAME", tenant_name)

        service = Phase1TestIdentityProvisioningService(session)
        first = service.provision()
        second = service.provision()

        assert first.user_id == second.user_id
        assert first.tenant_id == second.tenant_id
        assert first.user_created is True
        assert first.tenant_created is True
        assert second.user_created is False
        assert second.tenant_created is False

        binding = conn.execute(
            text(
                """
                SELECT pti.user_id,pti.tenant_id,pti.status,t.tenant_code,t.tenant_name,t.status AS tenant_status,
                       e.provider_subject
                FROM security.phase1_test_identity pti
                JOIN security.tenants t ON t.tenant_id=pti.tenant_id
                JOIN security.external_identities e
                  ON e.user_id=pti.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                WHERE pti.singleton_id=1
                """
            )
        ).mappings().one()
        assert str(binding["user_id"]) == first.user_id
        assert str(binding["tenant_id"]) == first.tenant_id
        assert binding["status"] == "ACTIVE"
        assert binding["tenant_status"] == "ACTIVE"
        assert binding["tenant_code"] == tenant_code
        assert binding["tenant_name"] == tenant_name
        assert binding["provider_subject"] == test_subject

        pc_default = set(
            str(value)
            for value in conn.execute(
                text(
                    """
                    SELECT permission_key
                    FROM security.platform_role_permission_defaults
                    WHERE role_key='PC' AND status='ACTIVE'
                    """
                )
            ).scalars()
        )
        test_tenant_pc = set(
            str(value)
            for value in conn.execute(
                text(
                    """
                    SELECT permission_key
                    FROM security.tenant_role_permissions
                    WHERE tenant_id=:tenant_id AND role_key='PC'
                    """
                ),
                {"tenant_id": first.tenant_id},
            ).scalars()
        )
        assert pc_default
        assert test_tenant_pc == pc_default

        assert conn.execute(
            text(
                """
                SELECT count(*) FROM security.user_tenant_operating_roles
                WHERE user_id=:user_id AND status='ACTIVE'
                """
            ),
            {"user_id": first.user_id},
        ).scalar_one() == 0
        assert conn.execute(
            text(
                """
                SELECT count(*) FROM security.user_admin_role_assignments
                WHERE user_id=:user_id AND status='ACTIVE'
                """
            ),
            {"user_id": first.user_id},
        ).scalar_one() == 0
    finally:
        session.close()
        outer.rollback()
        conn.close()
        engine.dispose()
