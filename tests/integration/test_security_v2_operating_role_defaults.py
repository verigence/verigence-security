from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.platform_admin import PlatformTenantService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

EXPECTED_DEFAULT_COUNTS = {
    "PC": 32,
    "TL": 32,
    "PM": 39,
    "CRM": 15,
    "Executive": 39,
}

_FULL_CONTACT_PERMISSION = "audit.customer.contact.full.read"


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


def test_platform_operating_role_defaults_match_approved_counts() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            counts = {
                str(row["role_key"]): int(row["permission_count"])
                for row in conn.execute(
                    text(
                        """
                        SELECT role_key,count(*) AS permission_count
                        FROM security.platform_role_permission_defaults
                        WHERE status='ACTIVE'
                          AND role_key IN ('PC','TL','PM','CRM','Executive')
                        GROUP BY role_key
                        """
                    )
                ).mappings()
            }
            assert counts == EXPECTED_DEFAULT_COUNTS

            executive = set(
                str(value)
                for value in conn.execute(
                    text(
                        """
                        SELECT permission_key
                        FROM security.platform_role_permission_defaults
                        WHERE role_key='Executive' AND status='ACTIVE'
                        """
                    )
                ).scalars()
            )
            assert "audit.master.write" in executive
            assert "audit.customer.write" in executive
            assert _FULL_CONTACT_PERMISSION in executive
            assert "audit.master.publish" not in executive
            assert "audit.journey.create" not in executive
            assert "di.requirement_profile.read" in executive
            assert "di.requirement_profile.write" not in executive

            ordinary_roles_with_full_contact = list(
                conn.execute(
                    text(
                        """
                        SELECT role_key
                        FROM security.platform_role_permission_defaults
                        WHERE permission_key=:permission_key
                          AND role_key IN ('PC','TL','PM','CRM')
                          AND status='ACTIVE'
                        ORDER BY role_key
                        """
                    ),
                    {"permission_key": _FULL_CONTACT_PERMISSION},
                ).scalars()
            )
            assert ordinary_roles_with_full_contact == []
    finally:
        engine.dispose()


def test_new_tenant_seed_copies_current_platform_defaults() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    actor_user_id = str(uuid4())
    tenant_id = str(uuid4())
    now = datetime.now(UTC)
    conn = engine.connect()
    transaction = conn.begin()
    session = Session(bind=conn)
    try:
        conn.execute(
            text(
                """
                INSERT INTO security.security_principals
                (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'USER','v2-default-seed-actor','ACTIVE',:now,:now)
                """
            ),
            {"user_id": actor_user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.users
                (user_id,display_name,status,created_at_utc,updated_at_utc)
                VALUES (:user_id,'v2-default-seed-actor','ACTIVE',:now,:now)
                """
            ),
            {"user_id": actor_user_id, "now": now},
        )
        conn.execute(
            text(
                """
                INSERT INTO security.tenants
                (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                VALUES (:tenant_id,:tenant_code,'V2 Default Seed Tenant','CONFIGURING',:now,:now)
                """
            ),
            {
                "tenant_id": tenant_id,
                "tenant_code": f"v2-default-{tenant_id}",
                "now": now,
            },
        )

        PlatformTenantService(session)._seed_v2_tenant_role_defaults(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            now=now,
        )

        platform_rows = set(
            (str(row["role_key"]), str(row["permission_key"]))
            for row in conn.execute(
                text(
                    """
                    SELECT d.role_key,d.permission_key
                    FROM security.platform_role_permission_defaults d
                    JOIN security.permissions p ON p.permission_key=d.permission_key
                    WHERE d.status='ACTIVE' AND p.status='ACTIVE'
                      AND d.role_key IN ('PC','TL','PM','CRM','Executive')
                    """
                )
            ).mappings()
        )
        tenant_rows = set(
            (str(row["role_key"]), str(row["permission_key"]))
            for row in conn.execute(
                text(
                    """
                    SELECT role_key,permission_key
                    FROM security.tenant_role_permissions
                    WHERE tenant_id=:tenant_id
                    """
                ),
                {"tenant_id": tenant_id},
            ).mappings()
        )
        assert tenant_rows == platform_rows
        assert len(tenant_rows) == sum(EXPECTED_DEFAULT_COUNTS.values())
        assert ("Executive", _FULL_CONTACT_PERMISSION) in tenant_rows
        assert all(
            (role_key, _FULL_CONTACT_PERMISSION) not in tenant_rows
            for role_key in ("PC", "TL", "PM", "CRM")
        )
    finally:
        session.close()
        transaction.rollback()
        conn.close()
        engine.dispose()
