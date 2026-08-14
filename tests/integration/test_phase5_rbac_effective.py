from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.core.errors import SecurityError
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.tenant_rbac_admin import TenantRbacAdminService

TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not TEST_DATABASE_URL, reason="Neon PostgreSQL required")


def _url(value: str) -> str:
    if value.startswith("postgresql+psycopg://"):
        return value
    for prefix in ("postgresql+asyncpg://", "postgresql://", "postgres://"):
        if value.startswith(prefix):
            return "postgresql+psycopg://" + value.removeprefix(prefix)
    raise ValueError("PostgreSQL URL required")


def test_group_and_direct_role_effective_rbac() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id, actor_id, member_id = (str(uuid4()) for _ in range(3))
    permission = f"test{uuid4().hex}.rbac.read"
    now = datetime.now(UTC)
    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:id,:code,'RBAC','ACTIVE',:now,:now)
                    """
                ),
                {"id": tenant_id, "code": f"rbac-{tenant_id}", "now": now},
            )
            for user_id in (actor_id, member_id):
                conn.execute(
                    text(
                        """
                        INSERT INTO security.security_principals
                        (principal_id,actor_type,principal_name,status,
                         created_at_utc,updated_at_utc)
                        VALUES (:id,'USER','RBAC','ACTIVE',:now,:now)
                        """
                    ),
                    {"id": user_id, "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.users
                        (user_id,display_name,status,created_at_utc,updated_at_utc)
                        VALUES (:id,'RBAC','ACTIVE',:now,:now)
                        """
                    ),
                    {"id": user_id, "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.tenant_memberships
                        (membership_id,tenant_id,user_id,status,authorization_version,
                         created_at_utc,updated_at_utc)
                        VALUES (:mid,:tenant_id,:user_id,'ACTIVE',1,:now,:now)
                        """
                    ),
                    {
                        "mid": str(uuid4()),
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "now": now,
                    },
                )
            module, resource, action = permission.split(".")
            conn.execute(
                text(
                    """
                    INSERT INTO security.permissions
                    (permission_key,module_key,resource_key,action_key,status,
                     display_name,catalog_version,updated_at_utc)
                    VALUES (:key,:module,:resource,:action,'ACTIVE','RBAC','test',:now)
                    """
                ),
                {
                    "key": permission,
                    "module": module,
                    "resource": resource,
                    "action": action,
                    "now": now,
                },
            )

        with Session(engine) as session:
            service = TenantRbacAdminService(session)
            role = service.create_role(
                tenant_id=tenant_id,
                role_key="PROCESS_CONSULTANT",
                role_name="Process Consultant",
                description=None,
                permission_keys=(permission,),
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            role_id = str(role["role_id"])
            group = service.create_group(
                tenant_id=tenant_id,
                group_key="PROCESS-CONSULTANTS",
                group_name="Process Consultants",
                description=None,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            group_id = str(group["group_id"])
            service.add_group_member(
                tenant_id=tenant_id,
                group_id=group_id,
                user_id=member_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            service.assign_group_role(
                tenant_id=tenant_id,
                group_id=group_id,
                role_id=role_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            roles, permissions = effective_user_permissions(
                session, tenant_id, member_id, datetime.now(UTC)
            )
            assert roles == ["PROCESS_CONSULTANT"]
            assert permissions == [permission]
            assert _version(session, tenant_id, member_id) == 3

            service.remove_group_role(
                tenant_id=tenant_id,
                group_id=group_id,
                role_id=role_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError) as denied:
                effective_user_permissions(session, tenant_id, member_id, datetime.now(UTC))
            assert denied.value.code == "ROLE_REQUIRED"

            service.assign_user_role(
                tenant_id=tenant_id,
                user_id=member_id,
                role_id=role_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            service.remove_role_permission(
                tenant_id=tenant_id,
                role_id=role_id,
                permission_key=permission,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError) as denied:
                effective_user_permissions(session, tenant_id, member_id, datetime.now(UTC))
            assert denied.value.code == "ROLE_REQUIRED"
            assert _version(session, tenant_id, member_id) == 6

            with pytest.raises(ValueError, match="Reserved role key"):
                service.create_role(
                    tenant_id=tenant_id,
                    role_key="tenant.fake_admin",
                    role_name="Fake",
                    description=None,
                    permission_keys=(),
                    actor_user_id=actor_id,
                    correlation_id=str(uuid4()),
                )
    finally:
        _cleanup(engine, tenant_id, actor_id, member_id, permission)
        engine.dispose()


def _version(session: Session, tenant_id: str, user_id: str) -> int:
    return int(
        session.execute(
            text(
                "SELECT authorization_version FROM security.tenant_memberships "
                "WHERE tenant_id=:tenant AND user_id=:user"
            ),
            {"tenant": tenant_id, "user": user_id},
        ).scalar_one()
    )


def _cleanup(
    engine: object,
    tenant_id: str,
    actor_id: str,
    member_id: str,
    permission: str,
) -> None:
    tables = (
        "admin_change_records",
        "group_role_assignments",
        "group_memberships",
        "groups",
        "user_role_assignments",
        "role_permissions",
        "roles",
        "tenant_memberships",
    )
    with engine.begin() as conn:  # type: ignore[union-attr]
        for table_name in tables:
            conn.execute(
                text(f"DELETE FROM security.{table_name} WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        conn.execute(
            text("DELETE FROM security.users WHERE user_id IN (:a,:m)"),
            {"a": actor_id, "m": member_id},
        )
        conn.execute(
            text("DELETE FROM security.security_principals WHERE principal_id IN (:a,:m)"),
            {"a": actor_id, "m": member_id},
        )
        conn.execute(text("DELETE FROM security.tenants WHERE tenant_id=:id"), {"id": tenant_id})
        # A temporary ACTIVE permission is automatically granted to platform.super_admin.
        # Retire it first so the v1.4.3 trigger removes that derived grant before deletion.
        conn.execute(
            text(
                "UPDATE security.permissions SET status='RETIRED',updated_at_utc=CURRENT_TIMESTAMP "
                "WHERE permission_key=:key"
            ),
            {"key": permission},
        )
        conn.execute(
            text("DELETE FROM security.permissions WHERE permission_key=:key"),
            {"key": permission},
        )
