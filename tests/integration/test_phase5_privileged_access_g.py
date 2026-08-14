from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.services.admin_control_plane_catalog import StandardTenantAdminRoleSeeder
from verigence_security.services.privileged_access import PrivilegedAccessService
from verigence_security.services.tenant_rbac_gate import TenantRbacGateService

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


def test_increment_g_privileged_role_requires_independent_checker() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    maker_id = str(uuid4())
    checker_id = str(uuid4())
    subject_id = str(uuid4())
    rejected_subject_id = str(uuid4())
    now = datetime.now(UTC)

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:code,'Increment G Maker Checker','ACTIVE',:now,:now)
                    """
                ),
                {"tenant_id": tenant_id, "code": f"g-{tenant_id}", "now": now},
            )
            for user_id, name in (
                (maker_id, "Increment G Maker"),
                (checker_id, "Increment G Checker"),
                (subject_id, "Increment G Subject"),
                (rejected_subject_id, "Increment G Rejected Subject"),
            ):
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

        with Session(engine) as session:
            assert StandardTenantAdminRoleSeeder(session).seed(tenant_id=tenant_id, now=now)

        with engine.begin() as conn:
            roles = {
                str(row["role_key"]): str(row["role_id"])
                for row in conn.execute(
                    text(
                        """
                        SELECT role_id,role_key FROM security.roles
                        WHERE tenant_id=:tenant_id
                        """
                    ),
                    {"tenant_id": tenant_id},
                ).mappings()
            }
            for user_id, role_key in (
                (maker_id, "tenant.rbac_admin"),
                (checker_id, "tenant.security_approver"),
            ):
                conn.execute(
                    text(
                        """
                        INSERT INTO security.user_role_assignments
                        (assignment_id,tenant_id,user_id,role_id,status,valid_from_utc,
                         assigned_by_user_id,assigned_at_utc)
                        VALUES (:id,:tenant_id,:user_id,:role_id,'ACTIVE',:now,:maker,:now)
                        """
                    ),
                    {
                        "id": str(uuid4()),
                        "tenant_id": tenant_id,
                        "user_id": user_id,
                        "role_id": roles[role_key],
                        "maker": maker_id,
                        "now": now,
                    },
                )

        with Session(engine) as session:
            gate = TenantRbacGateService(session)
            gate.authorize_user(
                tenant_id=tenant_id,
                user_id=maker_id,
                permission_key="security.role.assign",
            )
            gate.authorize_user(
                tenant_id=tenant_id,
                user_id=checker_id,
                permission_key="security.privileged_access.approve",
            )
            assert gate.assign_user_role(
                tenant_id=tenant_id,
                user_id=subject_id,
                role_id=roles["tenant.admin"],
                actor_user_id=maker_id,
                correlation_id=str(uuid4()),
            )

        with engine.connect() as conn:
            assert conn.execute(
                text(
                    """
                    SELECT 1 FROM security.user_role_assignments
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND role_id=:role_id
                      AND status='ACTIVE'
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "user_id": subject_id,
                    "role_id": roles["tenant.admin"],
                },
            ).first() is None
            request = conn.execute(
                text(
                    """
                    SELECT request_id,status,requested_by_user_id
                    FROM security.privileged_access_requests
                    WHERE tenant_id=:tenant_id AND subject_user_id=:user_id
                      AND role_id=:role_id
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "user_id": subject_id,
                    "role_id": roles["tenant.admin"],
                },
            ).mappings().one()
            request_id = str(request["request_id"])
            assert request["status"] == "PENDING"
            assert str(request["requested_by_user_id"]) == maker_id

        with Session(engine) as session, pytest.raises(ValueError, match="Requester cannot"):
            PrivilegedAccessService(session).approve(
                tenant_id=tenant_id,
                request_id=request_id,
                approver_user_id=maker_id,
                correlation_id=str(uuid4()),
                reason=None,
            )

        with Session(engine) as session, pytest.raises(ValueError, match="Subject cannot"):
            PrivilegedAccessService(session).approve(
                tenant_id=tenant_id,
                request_id=request_id,
                approver_user_id=subject_id,
                correlation_id=str(uuid4()),
                reason=None,
            )

        with Session(engine) as session:
            approved = PrivilegedAccessService(session).approve(
                tenant_id=tenant_id,
                request_id=request_id,
                approver_user_id=checker_id,
                correlation_id=str(uuid4()),
                reason="Independent checker approval",
            )
            assert approved["status"] == "APPROVED"
            assert approved["approvedByUserId"] == checker_id

        with engine.connect() as conn:
            assignment = conn.execute(
                text(
                    """
                    SELECT assigned_by_user_id FROM security.user_role_assignments
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND role_id=:role_id
                      AND status='ACTIVE'
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "user_id": subject_id,
                    "role_id": roles["tenant.admin"],
                },
            ).one()
            assert str(assignment[0]) == maker_id
            auth = conn.execute(
                text(
                    """
                    SELECT authorization_version FROM security.user_tenant_authorization_state
                    WHERE tenant_id=:tenant_id AND user_id=:user_id
                    """
                ),
                {"tenant_id": tenant_id, "user_id": subject_id},
            ).one()
            assert int(auth[0]) >= 2

        with Session(engine) as session:
            gate = TenantRbacGateService(session)
            assert gate.assign_user_role(
                tenant_id=tenant_id,
                user_id=rejected_subject_id,
                role_id=roles["tenant.security_policy_admin"],
                actor_user_id=maker_id,
                correlation_id=str(uuid4()),
            )
        with engine.connect() as conn:
            rejected_request_id = str(
                conn.execute(
                    text(
                        """
                        SELECT request_id FROM security.privileged_access_requests
                        WHERE tenant_id=:tenant_id AND subject_user_id=:user_id
                          AND role_id=:role_id AND status='PENDING'
                        """
                    ),
                    {
                        "tenant_id": tenant_id,
                        "user_id": rejected_subject_id,
                        "role_id": roles["tenant.security_policy_admin"],
                    },
                ).scalar_one()
            )

        with Session(engine) as session:
            rejected = PrivilegedAccessService(session).reject(
                tenant_id=tenant_id,
                request_id=rejected_request_id,
                approver_user_id=checker_id,
                correlation_id=str(uuid4()),
                reason="Rejected for test",
            )
            assert rejected["status"] == "REJECTED"

        with engine.connect() as conn:
            assert conn.execute(
                text(
                    """
                    SELECT 1 FROM security.user_role_assignments
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND role_id=:role_id
                      AND status='ACTIVE'
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "user_id": rejected_subject_id,
                    "role_id": roles["tenant.security_policy_admin"],
                },
            ).first() is None

        with Session(engine) as session:
            gate = TenantRbacGateService(session)
            assert gate.assign_user_role(
                tenant_id=tenant_id,
                user_id=rejected_subject_id,
                role_id=roles["tenant.user_admin"],
                actor_user_id=maker_id,
                correlation_id=str(uuid4()),
            )
        with engine.connect() as conn:
            assert conn.execute(
                text(
                    """
                    SELECT 1 FROM security.user_role_assignments
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND role_id=:role_id
                      AND status='ACTIVE'
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "user_id": rejected_subject_id,
                    "role_id": roles["tenant.user_admin"],
                },
            ).first() is not None
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.admin_change_records WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.privileged_access_requests WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.user_tenant_authorization_state WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.user_role_assignments WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            )
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
            for user_id in (maker_id, checker_id, subject_id, rejected_subject_id):
                conn.execute(text("DELETE FROM security.users WHERE user_id=:id"), {"id": user_id})
                conn.execute(
                    text("DELETE FROM security.security_principals WHERE principal_id=:id"),
                    {"id": user_id},
                )
        engine.dispose()
