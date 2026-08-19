from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.v2_rbac import (
    AdminRoleAssignmentService,
    OperatingRoleAssignmentService,
    RoleDefinitionService,
    TenantRoleBundleService,
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


def _create_module(
    conn: object,
    *,
    module_key: str,
    actor_user_id: str,
    now: datetime,
) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            INSERT INTO security.modules
            (module_key,module_name,catalog_version,status,created_at_utc,
             updated_at_utc,updated_by_user_id)
            VALUES (:module_key,:module_key,'v2-test','ACTIVE',:now,:now,:actor_user_id)
            """
        ),
        {"module_key": module_key, "actor_user_id": actor_user_id, "now": now},
    )


def _cleanup(
    conn: object,
    *,
    user_ids: list[str],
    tenant_ids: list[str],
    module_keys: list[str] | None = None,
) -> None:
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            DELETE FROM security.tenant_role_permissions
            WHERE tenant_id = ANY(:tenant_ids)
            """
        ),
        {"tenant_ids": tenant_ids},
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            DELETE FROM security.user_tenant_operating_roles
            WHERE user_id = ANY(:user_ids)
            """
        ),
        {"user_ids": user_ids},
    )
    conn.execute(  # type: ignore[attr-defined]
        text(
            """
            DELETE FROM security.user_admin_role_assignments
            WHERE user_id = ANY(:user_ids)
            """
        ),
        {"user_ids": user_ids},
    )
    if module_keys:
        conn.execute(  # type: ignore[attr-defined]
            text("DELETE FROM security.modules WHERE module_key = ANY(:module_keys)"),
            {"module_keys": module_keys},
        )
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


def test_v2_role_definition_and_tenant_bundle_services_use_only_v2_tables() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    actor_id = str(uuid4())
    tenant_id = str(uuid4())
    try:
        with engine.begin() as conn:
            _create_user(conn, user_id=actor_id, name="V2 bundle actor", now=now)
            _create_tenant(
                conn,
                tenant_id=tenant_id,
                code=f"v2-bundle-{tenant_id}",
                now=now,
            )

        with Session(engine) as session:
            roles = RoleDefinitionService(session).list_roles()
            role_by_key = {str(role["role_key"]): role for role in roles}
            assert role_by_key["PC"]["role_class"] == "OPERATING"
            assert role_by_key["TenantAdmin"]["role_class"] == "ADMIN"

            bundle_service = TenantRoleBundleService(session)
            result = bundle_service.replace_tenant_bundle(
                tenant_id=tenant_id,
                role_key="PC",
                permission_keys={"security.tenant.read", "security.module.read"},
                actor_user_id=actor_id,
            )
            assert result == ["security.module.read", "security.tenant.read"]
            assert bundle_service.tenant_bundle(tenant_id, "PC") == result

            with pytest.raises(ValueError, match="Permissions must exist and be ACTIVE"):
                bundle_service.replace_tenant_bundle(
                    tenant_id=tenant_id,
                    role_key="PC",
                    permission_keys={"does.not.exist"},
                    actor_user_id=actor_id,
                )

        with engine.connect() as conn:
            legacy_rows = conn.execute(
                text("SELECT count(*) FROM security.roles WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).scalar_one()
            assert int(legacy_rows) == 0
    finally:
        with engine.begin() as conn:
            _cleanup(conn, user_ids=[actor_id], tenant_ids=[tenant_id])
        engine.dispose()


def test_v2_operating_role_service_uses_set_replace_and_enforces_one_pm() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    actor_id = str(uuid4())
    user_a = str(uuid4())
    user_b = str(uuid4())
    tenant_a = str(uuid4())
    tenant_b = str(uuid4())
    users = [actor_id, user_a, user_b]
    tenants = [tenant_a, tenant_b]
    try:
        with engine.begin() as conn:
            _create_user(conn, user_id=actor_id, name="V2 role actor", now=now)
            _create_user(conn, user_id=user_a, name="V2 operating A", now=now)
            _create_user(conn, user_id=user_b, name="V2 operating B", now=now)
            _create_tenant(conn, tenant_id=tenant_a, code=f"v2-a-{tenant_a}", now=now)
            _create_tenant(conn, tenant_id=tenant_b, code=f"v2-b-{tenant_b}", now=now)

        with Session(engine) as session:
            service = OperatingRoleAssignmentService(session)
            first = service.set_role(
                tenant_id=tenant_a,
                user_id=user_a,
                role_key="PC",
                actor_user_id=actor_id,
            )
            assert first.changed

            same = service.set_role(
                tenant_id=tenant_a,
                user_id=user_a,
                role_key="PC",
                actor_user_id=actor_id,
            )
            assert not same.changed
            assert same.assignment_id == first.assignment_id

            replacement = service.set_role(
                tenant_id=tenant_a,
                user_id=user_a,
                role_key="TL",
                actor_user_id=actor_id,
            )
            assert replacement.changed
            assert replacement.assignment_id != first.assignment_id

            cross_tenant = service.set_role(
                tenant_id=tenant_b,
                user_id=user_a,
                role_key="CRM",
                actor_user_id=actor_id,
            )
            assert cross_tenant.changed

            pm = service.set_role(
                tenant_id=tenant_a,
                user_id=user_b,
                role_key="PM",
                actor_user_id=actor_id,
            )
            assert pm.changed

            with pytest.raises(ValueError, match="already has an ACTIVE PM"):
                service.set_role(
                    tenant_id=tenant_a,
                    user_id=user_a,
                    role_key="PM",
                    actor_user_id=actor_id,
                )

        with engine.connect() as conn:
            rows = list(
                conn.execute(
                    text(
                        """
                        SELECT tenant_id,role_key,status
                        FROM security.user_tenant_operating_roles
                        WHERE user_id=:user_id
                        ORDER BY tenant_id,status,role_key
                        """
                    ),
                    {"user_id": user_a},
                ).mappings()
            )
            active = [row for row in rows if row["status"] == "ACTIVE"]
            ended = [row for row in rows if row["status"] == "ENDED"]
            assert {str(row["role_key"]) for row in active} == {"TL", "CRM"}
            assert {str(row["role_key"]) for row in ended} == {"PC"}
    finally:
        with engine.begin() as conn:
            _cleanup(conn, user_ids=users, tenant_ids=tenants)
        engine.dispose()


def test_v2_admin_and_operating_roles_are_globally_exclusive_but_admins_stack() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    now = datetime.now(UTC)
    actor_id = str(uuid4())
    admin_user = str(uuid4())
    operating_user = str(uuid4())
    tenant_id = str(uuid4())
    module_key = f"v2mod{uuid4().hex[:10]}"
    users = [actor_id, admin_user, operating_user]
    try:
        with engine.begin() as conn:
            _create_user(conn, user_id=actor_id, name="V2 admin actor", now=now)
            _create_user(conn, user_id=admin_user, name="V2 admin subject", now=now)
            _create_user(conn, user_id=operating_user, name="V2 operating subject", now=now)
            _create_tenant(
                conn,
                tenant_id=tenant_id,
                code=f"v2-admin-{tenant_id}",
                now=now,
            )
            _create_module(
                conn,
                module_key=module_key,
                actor_user_id=actor_id,
                now=now,
            )

        with Session(engine) as session:
            admins = AdminRoleAssignmentService(session)
            operating = OperatingRoleAssignmentService(session)

            tenant_admin = admins.assign(
                user_id=admin_user,
                role_key="TenantAdmin",
                scope_id=tenant_id,
                actor_user_id=actor_id,
            )
            assert tenant_admin.changed

            module_admin = admins.assign(
                user_id=admin_user,
                role_key="ModuleAdmin",
                scope_id=module_key,
                actor_user_id=actor_id,
            )
            assert module_admin.changed

            with pytest.raises(
                ValueError,
                match="Administrative and operating roles are mutually exclusive",
            ):
                operating.set_role(
                    tenant_id=tenant_id,
                    user_id=admin_user,
                    role_key="PC",
                    actor_user_id=actor_id,
                )

            operating.set_role(
                tenant_id=tenant_id,
                user_id=operating_user,
                role_key="TL",
                actor_user_id=actor_id,
            )

            with pytest.raises(
                ValueError,
                match="Administrative and operating roles are mutually exclusive",
            ):
                admins.assign(
                    user_id=operating_user,
                    role_key="ModuleAdmin",
                    scope_id=module_key,
                    actor_user_id=actor_id,
                )

            removed = admins.remove(
                user_id=admin_user,
                role_key="TenantAdmin",
                scope_id=tenant_id,
            )
            assert removed.changed

        with engine.connect() as conn:
            remaining = list(
                conn.execute(
                    text(
                        """
                        SELECT role_key,status
                        FROM security.user_admin_role_assignments
                        WHERE user_id=:user_id
                        ORDER BY role_key
                        """
                    ),
                    {"user_id": admin_user},
                ).mappings()
            )
            assert {str(row["role_key"]) for row in remaining if row["status"] == "ACTIVE"} == {
                "ModuleAdmin"
            }
            assert {str(row["role_key"]) for row in remaining if row["status"] == "ENDED"} == {
                "TenantAdmin"
            }
    finally:
        with engine.begin() as conn:
            _cleanup(
                conn,
                user_ids=users,
                tenant_ids=[tenant_id],
                module_keys=[module_key],
            )
        engine.dispose()
