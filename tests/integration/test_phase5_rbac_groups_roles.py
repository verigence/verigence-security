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
pytestmark = pytest.mark.skipif(
    not TEST_DATABASE_URL,
    reason="TEST_DATABASE_URL is required for Neon/PostgreSQL integration tests",
)


def _url(url: str) -> str:
    if url.startswith("postgresql+psycopg://"):
        return url
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql+asyncpg://")
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url.removeprefix("postgresql://")
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url.removeprefix("postgres://")
    raise ValueError("TEST_DATABASE_URL must be PostgreSQL")


def test_group_and_direct_role_changes_drive_effective_rbac_and_versions() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    actor_id = str(uuid4())
    member_id = str(uuid4())
    permission_key = f"test{uuid4().hex}.rbac.read"
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:id,:code,'RBAC test','ACTIVE',:now,:now)
                    """
                ),
                {"id": tenant_id, "code": f"rbac-{tenant_id}", "now": now},
            )
            test_users = ((actor_id, "RBAC actor"), (member_id, "RBAC member"))
            for user_id, name in test_users:
                conn.execute(
                    text(
                        """
                        INSERT INTO security.security_principals
                        (principal_id,actor_type,principal_name,status,created_at_utc,updated_at_utc)
                        VALUES (:id,'USER',:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"id": user_id, "name": name, "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.users
                        (user_id,display_name,status,created_at_utc,updated_at_utc)
                        VALUES (:id,:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"id": user_id, "name": name, "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.tenant_memberships
                        (membership_id,tenant_id,user_id,status,authorization_version,
                         created_at_utc,updated_at_utc)
                        VALUES (:membership_id,:tenant_id,:user_id,'ACTIVE',1,:now,:now)
                        """
                    ),
                    {
                        "membership_id": str(uuid4()),
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "now": now,
                    },
                )
            parts = permission_key.split(".")
            conn.execute(
                text(
                    """
                    INSERT INTO security.permissions
                    (permission_key,module_key,resource_key,action_key,description,status,
                     display_name,catalog_version,updated_at_utc)
                    VALUES (:key,:module,:resource,:action,'RBAC test','ACTIVE',
                            'RBAC test','test',:now)
                    """
                ),
                {
                    "key": permission_key,
                    "module": parts[0],
                    "resource": parts[1],
                    "action": parts[2],
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
                permission_keys=(permission_key,),
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

            assert service.add_group_member(
                tenant_id=tenant_id,
                group_id=group_id,
                user_id=member_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            assert service.assign_group_role(
                tenant_id=tenant_id,
                group_id=group_id,
                role_id=role_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )

            roles, permissions = effective_user_permissions(
                session,
                tenant_id,
                member_id,
                datetime.now(UTC),
            )
            assert roles == ["PROCESS_CONSULTANT"]
            assert permissions == [permission_key]
            version = session.execute(
                text(
                    "SELECT authorization_version FROM security.tenant_memberships "
                    "WHERE tenant_id=:tenant_id AND user_id=:user_id"
                ),
                {"tenant_id": tenant_id, "user_id": member_id},
            ).scalar_one()
            assert version == 3

            assert service.remove_group_role(
                tenant_id=tenant_id,
                group_id=group_id,
                role_id=role_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError) as exc_info:
                effective_user_permissions(session, tenant_id, member_id, datetime.now(UTC))
            assert exc_info.value.code == "ROLE_REQUIRED"

            assert service.assign_user_role(
                tenant_id=tenant_id,
                user_id=member_id,
                role_id=role_id,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            roles, permissions = effective_user_permissions(
                session,
                tenant_id,
                member_id,
                datetime.now(UTC),
            )
            assert roles == ["PROCESS_CONSULTANT"]
            assert permissions == [permission_key]

            assert service.remove_role_permission(
                tenant_id=tenant_id,
                role_id=role_id,
                permission_key=permission_key,
                actor_user_id=actor_id,
                correlation_id=str(uuid4()),
            )
            with pytest.raises(SecurityError) as exc_info:
                effective_user_permissions(session, tenant_id, member_id, datetime.now(UTC))
            assert exc_info.value.code == "ROLE_REQUIRED"

            version = session.execute(
                text(
                    "SELECT authorization_version FROM security.tenant_memberships "
                    "WHERE tenant_id=:tenant_id AND user_id=:user_id"
                ),
                {"tenant_id": tenant_id, "user_id": member_id},
            ).scalar_one()
            assert version == 6

            audit_count = session.execute(
                text(
                    "SELECT count(*) FROM security.admin_change_records "
                    "WHERE tenant_id=:tenant_id AND actor_user_id=:actor_id"
                ),
                {"tenant_id": tenant_id, "actor_id": actor_id},
            ).scalar_one()
            assert audit_count >= 7

            with pytest.raises(ValueError, match="Reserved role key"):
                service.create_role(
                    tenant_id=tenant_id,
                    role_key="tenant.fake_admin",
                    role_name="Fake Admin",
                    description=None,
                    permission_keys=(),
                    actor_user_id=actor_id,
                    correlation_id=str(uuid4()),
                )
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.admin_change_records WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.group_role_assignments WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.group_memberships WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(text("DELETE FROM security.groups WHERE tenant_id=:id"), {"id": tenant_id})
            conn.execute(
                text("DELETE FROM security.user_role_assignments WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.role_permissions WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(text("DELETE FROM security.roles WHERE tenant_id=:id"), {"id": tenant_id})
            conn.execute(
                text("DELETE FROM security.tenant_memberships WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id IN (:actor_id,:member_id)"),
                {"actor_id": actor_id, "member_id": member_id},
            )
            conn.execute(
                text(
                    "DELETE FROM security.security_principals "
                    "WHERE principal_id IN (:actor_id,:member_id)"
                ),
                {"actor_id": actor_id, "member_id": member_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.permissions WHERE permission_key=:key"),
                {"key": permission_key},
            )
        engine.dispose()
