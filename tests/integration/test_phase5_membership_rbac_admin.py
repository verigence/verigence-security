from __future__ import annotations

import os
from datetime import UTC, datetime, time
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.tenant_access_configuration import (
    AccessScheduleConfiguration,
    AccessScheduleWindowConfiguration,
    TenantAccessConfigurationService,
    TenantLocationConfiguration,
)
from verigence_security.services.tenant_authorization_configuration import (
    PermissionConfiguration,
    TenantAuthorizationConfigurationService,
    TenantMembershipConfiguration,
    TenantRoleConfiguration,
    UserLocationConfiguration,
    UserRoleConfiguration,
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


def test_administered_membership_location_and_rbac_feed_runtime_authorization() -> None:
    assert TEST_DATABASE_URL is not None
    engine = create_engine(_sqlalchemy_url(TEST_DATABASE_URL), pool_pre_ping=True)
    tenant_id = str(uuid4())
    admin_user_id = str(uuid4())
    employee_user_id = str(uuid4())
    membership_id = str(uuid4())
    location_id = str(uuid4())
    schedule_id = str(uuid4())
    window_id = str(uuid4())
    role_id = str(uuid4())
    role_assignment_id = str(uuid4())
    location_assignment_id = str(uuid4())
    permission_key = "di.document.upload"
    now = datetime.now(UTC)
    original_permission: dict[str, object] | None = None

    try:
        with engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO security.tenants
                    (tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc)
                    VALUES (:tenant_id,:tenant_code,'Phase 5 Authorization Admin',
                            'CONFIGURING',:now,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "tenant_code": f"p5-auth-{tenant_id}",
                    "now": now,
                },
            )
            for user_id, name in (
                (admin_user_id, "Phase 5 Administrator"),
                (employee_user_id, "Phase 5 Employee"),
            ):
                conn.execute(
                    text(
                        """
                        INSERT INTO security.security_principals
                        (principal_id,actor_type,principal_name,status,
                         created_at_utc,updated_at_utc)
                        VALUES (:user_id,'USER',:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"user_id": user_id, "name": name, "now": now},
                )
                conn.execute(
                    text(
                        """
                        INSERT INTO security.users
                        (user_id,display_name,status,created_at_utc,updated_at_utc)
                        VALUES (:user_id,:name,'ACTIVE',:now,:now)
                        """
                    ),
                    {"user_id": user_id, "name": name, "now": now},
                )
            existing = conn.execute(
                text("SELECT * FROM security.permissions WHERE permission_key=:key"),
                {"key": permission_key},
            ).mappings().first()
            original_permission = dict(existing) if existing is not None else None

        with Session(engine) as session:  # type: ignore[arg-type]
            access_admin = TenantAccessConfigurationService(session)
            assert access_admin.configure_location(
                tenant_id=tenant_id,
                configuration=TenantLocationConfiguration(
                    location_id=location_id,
                    location_code="P5-AUTH-LOC",
                    location_name="Phase 5 Authorized Location",
                    location_type="OFFICE",
                    latitude=28.6139,
                    longitude=77.2090,
                    allowed_radius_meters=300,
                    timezone_iana="Asia/Kolkata",
                    address_line1=None,
                    city="New Delhi",
                    state_region="Delhi",
                    country_code="IN",
                    postal_code=None,
                    status="ACTIVE",
                ),
                now=now,
            )
            assert access_admin.configure_schedule(
                tenant_id=tenant_id,
                configuration=AccessScheduleConfiguration(
                    schedule_id=schedule_id,
                    schedule_key="P5-AUTH-SCHEDULE",
                    schedule_name="Phase 5 Authorization Schedule",
                    status="ACTIVE",
                    windows=(
                        AccessScheduleWindowConfiguration(
                            schedule_window_id=window_id,
                            iso_day_of_week=1,
                            start_local_time=time(9, 0),
                            end_local_time=time(18, 0),
                            crosses_midnight=False,
                            status="ACTIVE",
                        ),
                    ),
                ),
                now=now,
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            auth_admin = TenantAuthorizationConfigurationService(session)
            assert auth_admin.configure_membership(
                tenant_id=tenant_id,
                user_id=employee_user_id,
                configuration=TenantMembershipConfiguration(
                    membership_id=membership_id,
                    employee_code="P5-EMP-001",
                    status="ACTIVE",
                    valid_from_utc=None,
                    valid_to_utc=None,
                    authorization_version=4,
                ),
                now=now,
            )
            auth_admin.configure_permission(
                PermissionConfiguration(
                    permission_key=permission_key,
                    module_key="di",
                    resource_key="document",
                    action_key="upload",
                    description="Canonical document upload permission",
                    status="ACTIVE",
                )
            )
            assert auth_admin.configure_role(
                tenant_id=tenant_id,
                configuration=TenantRoleConfiguration(
                    role_id=role_id,
                    role_key="PHASE5_PROCESS_CONSULTANT",
                    role_name="Phase 5 Process Consultant",
                    description="Phase 5 integration fixture",
                    status="ACTIVE",
                    permission_keys=(permission_key,),
                ),
                now=now,
            )
            assert auth_admin.assign_user_role(
                tenant_id=tenant_id,
                user_id=employee_user_id,
                configuration=UserRoleConfiguration(
                    assignment_id=role_assignment_id,
                    role_key="PHASE5_PROCESS_CONSULTANT",
                    valid_from_utc=None,
                    valid_to_utc=None,
                    status="ACTIVE",
                ),
                assigned_by_user_id=admin_user_id,
                now=now,
            )
            assert auth_admin.assign_user_location(
                tenant_id=tenant_id,
                user_id=employee_user_id,
                configuration=UserLocationConfiguration(
                    assignment_id=location_assignment_id,
                    location_id=location_id,
                    schedule_id=schedule_id,
                    valid_from_utc=None,
                    valid_to_utc=None,
                    status="ACTIVE",
                ),
                assigned_by_user_id=admin_user_id,
                now=now,
            )

        with Session(engine) as session:  # type: ignore[arg-type]
            runtime = SecurityRepository(session)
            context = runtime.get_user_context(employee_user_id, tenant_id, now)
            assert context.membership_id == membership_id
            assert context.membership_status == "ACTIVE"
            assert context.authorization_version == 4

            locations = runtime.assigned_locations(employee_user_id, tenant_id, now)
            assert len(locations) == 1
            assert locations[0].location_id == location_id
            assert locations[0].schedule_id == schedule_id

            roles, permissions = runtime.effective_user_permissions(
                tenant_id,
                employee_user_id,
                now,
            )
            assert roles == ["PHASE5_PROCESS_CONSULTANT"]
            assert permissions == [permission_key]
    finally:
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM security.user_location_assignments WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.user_role_assignments WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.role_permissions WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.roles WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_memberships WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.access_schedule_windows WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.access_schedules WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            conn.execute(
                text("DELETE FROM security.tenant_locations WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
            if original_permission is None:
                conn.execute(
                    text("DELETE FROM security.permissions WHERE permission_key=:key"),
                    {"key": permission_key},
                )
            else:
                conn.execute(
                    text(
                        """
                        UPDATE security.permissions
                        SET module_key=:module_key,resource_key=:resource_key,
                            action_key=:action_key,description=:description,status=:status
                        WHERE permission_key=:permission_key
                        """
                    ),
                    original_permission,
                )
            conn.execute(
                text("DELETE FROM security.users WHERE user_id IN (:admin_id,:employee_id)"),
                {"admin_id": admin_user_id, "employee_id": employee_user_id},
            )
            conn.execute(
                text(
                    "DELETE FROM security.security_principals "
                    "WHERE principal_id IN (:admin_id,:employee_id)"
                ),
                {"admin_id": admin_user_id, "employee_id": employee_user_id},
            )
            conn.execute(
                text("DELETE FROM security.tenants WHERE tenant_id=:id"),
                {"id": tenant_id},
            )
        engine.dispose()
