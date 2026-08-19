from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)

V2_TABLES = frozenset(
    {
        "role_definitions",
        "platform_role_permission_defaults",
        "tenant_role_permissions",
        "user_tenant_operating_roles",
        "user_admin_role_assignments",
    }
)

LEGACY_TABLES_THAT_MUST_REMAIN = frozenset(
    {
        "roles",
        "role_permissions",
        "user_role_assignments",
        "groups",
        "group_memberships",
        "group_role_assignments",
    }
)

EXPECTED_ROLE_DEFINITIONS = {
    "PC": "OPERATING",
    "TL": "OPERATING",
    "PM": "OPERATING",
    "CRM": "OPERATING",
    "Executive": "OPERATING",
    "TenantAdmin": "ADMIN",
    "ModuleAdmin": "ADMIN",
    "SuperAdmin": "ADMIN",
    "TestUser": "TEST",
}


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


def _create_user(conn: object, *, user_id: str, name: str, now: datetime) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.security_principals
            (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,'USER',:name,'ACTIVE',:now,:now)
            """
        ),
        {"user_id": user_id, "name": name, "now": now},
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.users
            (user_id,display_name,status,created_at_utc,updated_at_utc)
            VALUES (:user_id,:name,'ACTIVE',:now,:now)
            """
        ),
        {"user_id": user_id, "name": name, "now": now},
    )


def _create_tenant(conn: object, *, tenant_id: str, code: str, now: datetime) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.tenants
            (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
            VALUES (:tenant_id,:code,:code,'ACTIVE',:now,:now)
            """
        ),
        {"tenant_id": tenant_id, "code": code, "now": now},
    )


def _cleanup_users_and_tenants(
    conn: object, *, user_ids: list[str], tenant_ids: list[str]
) -> None:
    for user_id in user_ids:
        conn.execute(  # type: ignore[attr-defined]
            text("DELETE FROM security.users WHERE user_id=:user_id"),
            {"user_id": user_id},
        )
        conn.execute(  # type: ignore[attr-defined]
            text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
            {"user_id": user_id},
        )
    for tenant_id in tenant_ids:
        conn.execute(  # type: ignore[attr-defined]
            text("DELETE FROM security.tenants WHERE tenant_id=:tenant_id"),
            {"tenant_id": tenant_id},
        )


def test_v2_role_foundation_tables_and_fixed_role_catalogue_exist() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    try:
        with engine.connect() as conn:
            tables = frozenset(
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
            )
            assert tables >= V2_TABLES
            assert tables >= LEGACY_TABLES_THAT_MUST_REMAIN

            roles = {
                str(row["role_key"]): str(row["role_class"])
                for row in conn.execute(
                    text(
                        """
                        SELECT role_key,role_class
                        FROM security.role_definitions
                        WHERE status='ACTIVE'
                        """
                    )
                ).mappings()
            }
            for role_key, role_class in EXPECTED_ROLE_DEFINITIONS.items():
                assert roles.get(role_key) == role_class
    finally:
        engine.dispose()


def test_v2_operating_role_cardinality_and_one_pm_per_tenant() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    user_a = str(uuid4())
    user_b = str(uuid4())
    user_c = str(uuid4())
    user_ids = [user_a, user_b, user_c]
    tenant_ids = [tenant_a, tenant_b]
    try:
        with engine.begin() as conn:
            _create_tenant(conn, tenant_id=tenant_a, code=f"v2-a-{tenant_a}", now=now)
            _create_tenant(conn, tenant_id=tenant_b, code=f"v2-b-{tenant_b}", now=now)
            _create_user(conn, user_id=user_a, name="V2 role user A", now=now)
            _create_user(conn, user_id=user_b, name="V2 role user B", now=now)
            _create_user(conn, user_id=user_c, name="V2 role user C", now=now)

            conn.execute(
                text(
                    """
                    INSERT INTO security.user_tenant_operating_roles
                    (assignment_id,user_id,tenant_id,role_key,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:user_id,:tenant_id,'PC','ACTIVE',:actor_id,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "user_id": user_a,
                    "tenant_id": tenant_a,
                    "actor_id": user_a,
                    "now": now,
                },
            )

            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        """
                            INSERT INTO security.user_tenant_operating_roles
                            (assignment_id,user_id,tenant_id,role_key,status,
                             assigned_by_user_id,assigned_at_utc)
                            VALUES (:id,:user_id,:tenant_id,'TL','ACTIVE',:actor_id,:now)
                            """
                    ),
                    {
                        "id": str(uuid4()),
                        "user_id": user_a,
                        "tenant_id": tenant_a,
                        "actor_id": user_a,
                        "now": now,
                    },
                )

            conn.execute(
                text(
                    """
                    INSERT INTO security.user_tenant_operating_roles
                    (assignment_id,user_id,tenant_id,role_key,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:user_id,:tenant_id,'TL','ACTIVE',:actor_id,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "user_id": user_a,
                    "tenant_id": tenant_b,
                    "actor_id": user_a,
                    "now": now,
                },
            )

            conn.execute(
                text(
                    """
                    INSERT INTO security.user_tenant_operating_roles
                    (assignment_id,user_id,tenant_id,role_key,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:user_id,:tenant_id,'PM','ACTIVE',:actor_id,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "user_id": user_b,
                    "tenant_id": tenant_a,
                    "actor_id": user_a,
                    "now": now,
                },
            )

            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        """
                            INSERT INTO security.user_tenant_operating_roles
                            (assignment_id,user_id,tenant_id,role_key,status,
                             assigned_by_user_id,assigned_at_utc)
                            VALUES (:id,:user_id,:tenant_id,'PM','ACTIVE',:actor_id,:now)
                            """
                    ),
                    {
                        "id": str(uuid4()),
                        "user_id": user_c,
                        "tenant_id": tenant_a,
                        "actor_id": user_a,
                        "now": now,
                    },
                )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM security.user_tenant_operating_roles "
                    "WHERE user_id IN (:user_a,:user_b,:user_c)"
                ),
                {"user_a": user_a, "user_b": user_b, "user_c": user_c},
            )
            _cleanup_users_and_tenants(conn, user_ids=user_ids, tenant_ids=tenant_ids)
        engine.dispose()


def test_v2_admin_scope_shapes_and_single_super_admin() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    tenant_id = str(uuid4())
    user_a = str(uuid4())
    user_b = str(uuid4())
    user_ids = [user_a, user_b]
    try:
        with engine.begin() as conn:
            _create_tenant(conn, tenant_id=tenant_id, code=f"v2-admin-{tenant_id}", now=now)
            _create_user(conn, user_id=user_a, name="V2 admin user A", now=now)
            _create_user(conn, user_id=user_b, name="V2 admin user B", now=now)

            conn.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:user_id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',NULL,:now)
                    """
                ),
                {"id": str(uuid4()), "user_id": user_a, "now": now},
            )

            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        """
                            INSERT INTO security.user_admin_role_assignments
                            (assignment_id,user_id,role_key,scope_type,scope_id,status,
                             assigned_by_user_id,assigned_at_utc)
                            VALUES (:id,:user_id,'SuperAdmin','PLATFORM',NULL,'ACTIVE',NULL,:now)
                            """
                    ),
                    {"id": str(uuid4()), "user_id": user_b, "now": now},
                )

            conn.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:user_id,'TenantAdmin','TENANT',:scope_id,'ACTIVE',:actor_id,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "user_id": user_b,
                    "scope_id": tenant_id,
                    "actor_id": user_a,
                    "now": now,
                },
            )

            conn.execute(
                text(
                    """
                    INSERT INTO security.user_admin_role_assignments
                    (assignment_id,user_id,role_key,scope_type,scope_id,status,
                     assigned_by_user_id,assigned_at_utc)
                    VALUES (:id,:user_id,'ModuleAdmin','MODULE','di','ACTIVE',:actor_id,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "user_id": user_b,
                    "actor_id": user_a,
                    "now": now,
                },
            )

            with pytest.raises(IntegrityError), conn.begin_nested():
                conn.execute(
                    text(
                        """
                            INSERT INTO security.user_admin_role_assignments
                            (assignment_id,user_id,role_key,scope_type,scope_id,status,
                             assigned_by_user_id,assigned_at_utc)
                            VALUES (:id,:user_id,'TenantAdmin','MODULE','di','ACTIVE',:actor_id,:now)
                            """
                    ),
                    {
                        "id": str(uuid4()),
                        "user_id": user_b,
                        "actor_id": user_a,
                        "now": now,
                    },
                )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM security.user_admin_role_assignments "
                    "WHERE user_id IN (:user_a,:user_b)"
                ),
                {"user_a": user_a, "user_b": user_b},
            )
            _cleanup_users_and_tenants(conn, user_ids=user_ids, tenant_ids=[tenant_id])
        engine.dispose()
