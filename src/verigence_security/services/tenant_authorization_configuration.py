from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from verigence_security.repositories.admin_repository import SecurityAdminRepository
from verigence_security.repositories.membership_admin_repository import (
    MembershipAdminRepository,
)
from verigence_security.repositories.rbac_admin_repository import RbacAdminRepository
from verigence_security.repositories.user_location_admin_repository import (
    UserLocationAdminRepository,
)
from verigence_security.services.permissions import is_canonical_permission


@dataclass(frozen=True, slots=True)
class TenantMembershipConfiguration:
    membership_id: str
    employee_code: str | None
    status: str
    valid_from_utc: datetime | None
    valid_to_utc: datetime | None
    authorization_version: int


@dataclass(frozen=True, slots=True)
class PermissionConfiguration:
    permission_key: str
    module_key: str
    resource_key: str
    action_key: str
    description: str | None
    status: str


@dataclass(frozen=True, slots=True)
class TenantRoleConfiguration:
    role_id: str
    role_key: str
    role_name: str
    description: str | None
    status: str
    permission_keys: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UserRoleConfiguration:
    assignment_id: str
    role_key: str
    valid_from_utc: datetime | None
    valid_to_utc: datetime | None
    status: str


@dataclass(frozen=True, slots=True)
class UserLocationConfiguration:
    assignment_id: str
    location_id: str
    schedule_id: str
    valid_from_utc: datetime | None
    valid_to_utc: datetime | None
    status: str


class TenantAuthorizationConfigurationService:
    """Internal administration for existing-user Tenant authorization context."""

    def __init__(self, session: Session) -> None:
        self.admin = SecurityAdminRepository(session)
        self.memberships = MembershipAdminRepository(session)
        self.rbac = RbacAdminRepository(session)
        self.user_locations = UserLocationAdminRepository(session)

    def configure_membership(
        self,
        *,
        tenant_id: str,
        user_id: str,
        configuration: TenantMembershipConfiguration,
        now: datetime,
    ) -> bool:
        try:
            if self.admin.tenant(tenant_id) is None or not self.memberships.user_exists(user_id):
                self.memberships.rollback()
                return False
            self.memberships.upsert_membership(
                membership_id=configuration.membership_id,
                tenant_id=tenant_id,
                user_id=user_id,
                employee_code=configuration.employee_code,
                status=configuration.status,
                valid_from_utc=configuration.valid_from_utc,
                valid_to_utc=configuration.valid_to_utc,
                authorization_version=configuration.authorization_version,
                now=now,
            )
            self.memberships.commit()
            return True
        except Exception:
            self.memberships.rollback()
            raise

    def configure_permission(self, configuration: PermissionConfiguration) -> None:
        if not is_canonical_permission(configuration.permission_key):
            raise ValueError("permission_key must use canonical dot notation")
        try:
            self.rbac.upsert_permission(
                permission_key=configuration.permission_key,
                module_key=configuration.module_key,
                resource_key=configuration.resource_key,
                action_key=configuration.action_key,
                description=configuration.description,
                status=configuration.status,
            )
            self.rbac.commit()
        except Exception:
            self.rbac.rollback()
            raise

    def configure_role(
        self,
        *,
        tenant_id: str,
        configuration: TenantRoleConfiguration,
        now: datetime,
    ) -> bool:
        try:
            if self.admin.tenant(tenant_id) is None:
                self.rbac.rollback()
                return False
            self.rbac.upsert_role(
                role_id=configuration.role_id,
                tenant_id=tenant_id,
                role_key=configuration.role_key,
                role_name=configuration.role_name,
                description=configuration.description,
                status=configuration.status,
                now=now,
            )
            role = self.rbac.role(tenant_id=tenant_id, role_key=configuration.role_key)
            if role is None:
                self.rbac.rollback()
                return False
            for permission_key in configuration.permission_keys:
                if not is_canonical_permission(permission_key):
                    raise ValueError("role permission must use canonical dot notation")
                self.rbac.assign_permission(
                    tenant_id=tenant_id,
                    role_id=str(role["role_id"]),
                    permission_key=permission_key,
                    assigned_at=now,
                )
            self.rbac.commit()
            return True
        except Exception:
            self.rbac.rollback()
            raise

    def assign_user_role(
        self,
        *,
        tenant_id: str,
        user_id: str,
        configuration: UserRoleConfiguration,
        assigned_by_user_id: str,
        now: datetime,
    ) -> bool:
        try:
            membership = self.memberships.membership(tenant_id=tenant_id, user_id=user_id)
            role = self.rbac.role(tenant_id=tenant_id, role_key=configuration.role_key)
            if membership is None or role is None:
                self.rbac.rollback()
                return False
            self.rbac.assign_user_role(
                assignment_id=configuration.assignment_id,
                tenant_id=tenant_id,
                user_id=user_id,
                role_id=str(role["role_id"]),
                valid_from_utc=configuration.valid_from_utc,
                valid_to_utc=configuration.valid_to_utc,
                status=configuration.status,
                assigned_by_user_id=assigned_by_user_id,
                assigned_at=now,
            )
            self.rbac.commit()
            return True
        except Exception:
            self.rbac.rollback()
            raise

    def assign_user_location(
        self,
        *,
        tenant_id: str,
        user_id: str,
        configuration: UserLocationConfiguration,
        assigned_by_user_id: str,
        now: datetime,
    ) -> bool:
        try:
            if self.memberships.membership(tenant_id=tenant_id, user_id=user_id) is None:
                self.user_locations.rollback()
                return False
            self.user_locations.assign(
                assignment_id=configuration.assignment_id,
                tenant_id=tenant_id,
                user_id=user_id,
                location_id=configuration.location_id,
                schedule_id=configuration.schedule_id,
                valid_from_utc=configuration.valid_from_utc,
                valid_to_utc=configuration.valid_to_utc,
                status=configuration.status,
                assigned_by_user_id=assigned_by_user_id,
                assigned_at=now,
            )
            self.user_locations.commit()
            return True
        except Exception:
            self.user_locations.rollback()
            raise
