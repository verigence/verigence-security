from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy.orm import Session
from sqlalchemy import text


SECURITY_ADMIN_PERMISSION_KEYS: frozenset[str] = frozenset(
    {
        "security.platform_admin.read",
        "security.platform_admin.manage",
        "security.security_config.read",
        "security.security_config.manage",
        "security.tenant.create",
        "security.tenant.read",
        "security.tenant.update",
        "security.tenant.suspend",
        "security.tenant.activate",
        "security.tenant.bootstrap_admin",
        "security.module.read",
        "security.module.manage",
        "security.permission.read",
        "security.audit.read",
        "security.member.read",
        "security.member.invite",
        "security.member.update",
        "security.member.suspend",
        "security.member.end",
        "security.member.approve",
        "security.group.read",
        "security.group.create",
        "security.group.update",
        "security.group.assign",
        "security.role.read",
        "security.role.create",
        "security.role.update",
        "security.role.assign",
        "security.location.read",
        "security.location.create",
        "security.location.update",
        "security.location.assign",
        "security.schedule.read",
        "security.schedule.create",
        "security.schedule.update",
        "security.device.read",
        "security.device.approve",
        "security.device.block",
        "security.device.revoke",
        "security.policy.read",
        "security.policy.update",
        "security.retention.read",
        "security.retention.update",
        "security.privileged_access.approve",
    }
)

STANDARD_PLATFORM_ROLE_BUNDLES: dict[str, frozenset[str]] = {
    "platform.super_admin": frozenset(
        {
            "security.platform_admin.read",
            "security.platform_admin.manage",
            "security.security_config.read",
            "security.security_config.manage",
            "security.tenant.create",
            "security.tenant.read",
            "security.tenant.update",
            "security.tenant.suspend",
            "security.tenant.activate",
            "security.tenant.bootstrap_admin",
            "security.module.read",
            "security.module.manage",
            "security.permission.read",
            "security.audit.read",
        }
    ),
    "platform.security_admin": frozenset(
        {
            "security.security_config.read",
            "security.security_config.manage",
            "security.platform_admin.read",
            "security.tenant.read",
            "security.audit.read",
        }
    ),
    "platform.module_catalog_admin": frozenset(
        {
            "security.module.read",
            "security.module.manage",
            "security.permission.read",
            "security.audit.read",
        }
    ),
    "platform.auditor": frozenset(
        {
            "security.platform_admin.read",
            "security.security_config.read",
            "security.tenant.read",
            "security.module.read",
            "security.permission.read",
            "security.audit.read",
        }
    ),
}


@dataclass(frozen=True, slots=True)
class StandardTenantAdminRole:
    role_key: str
    role_name: str
    description: str
    permission_keys: frozenset[str]


_TENANT_OWNER_PERMISSIONS = frozenset(
    {
        "security.member.read",
        "security.member.invite",
        "security.member.update",
        "security.member.suspend",
        "security.member.end",
        "security.member.approve",
        "security.group.read",
        "security.group.create",
        "security.group.update",
        "security.group.assign",
        "security.role.read",
        "security.role.create",
        "security.role.update",
        "security.role.assign",
        "security.permission.read",
        "security.location.read",
        "security.location.create",
        "security.location.update",
        "security.location.assign",
        "security.schedule.read",
        "security.schedule.create",
        "security.schedule.update",
        "security.device.read",
        "security.device.approve",
        "security.device.block",
        "security.device.revoke",
        "security.policy.read",
        "security.policy.update",
        "security.retention.read",
        "security.retention.update",
        "security.privileged_access.approve",
        "security.audit.read",
    }
)

STANDARD_TENANT_ADMIN_ROLES: tuple[StandardTenantAdminRole, ...] = (
    StandardTenantAdminRole(
        role_key="tenant.owner",
        role_name="Tenant Owner",
        description="Highest authority inside one Tenant",
        permission_keys=_TENANT_OWNER_PERMISSIONS,
    ),
    StandardTenantAdminRole(
        role_key="tenant.admin",
        role_name="Tenant Admin",
        description="Day-to-day Tenant Security administration",
        permission_keys=frozenset(
            {
                "security.member.read",
                "security.member.invite",
                "security.member.update",
                "security.member.suspend",
                "security.member.end",
                "security.group.read",
                "security.group.create",
                "security.group.update",
                "security.group.assign",
                "security.role.read",
                "security.role.create",
                "security.role.update",
                "security.role.assign",
                "security.permission.read",
                "security.location.read",
                "security.location.create",
                "security.location.update",
                "security.location.assign",
                "security.schedule.read",
                "security.schedule.create",
                "security.schedule.update",
                "security.device.read",
                "security.device.approve",
                "security.device.block",
                "security.device.revoke",
                "security.policy.read",
                "security.retention.read",
                "security.audit.read",
            }
        ),
    ),
    StandardTenantAdminRole(
        role_key="tenant.user_admin",
        role_name="User Admin",
        description="Member invitation and lifecycle administration",
        permission_keys=frozenset(
            {
                "security.member.read",
                "security.member.invite",
                "security.member.update",
                "security.member.suspend",
                "security.member.end",
            }
        ),
    ),
    StandardTenantAdminRole(
        role_key="tenant.rbac_admin",
        role_name="Role & Group Admin",
        description="Roles, Groups and assignment administration",
        permission_keys=frozenset(
            {
                "security.member.read",
                "security.group.read",
                "security.group.create",
                "security.group.update",
                "security.group.assign",
                "security.role.read",
                "security.role.create",
                "security.role.update",
                "security.role.assign",
                "security.permission.read",
                "security.audit.read",
            }
        ),
    ),
    StandardTenantAdminRole(
        role_key="tenant.access_admin",
        role_name="Access Admin",
        description="Locations, schedules and device administration",
        permission_keys=frozenset(
            {
                "security.member.read",
                "security.location.read",
                "security.location.create",
                "security.location.update",
                "security.location.assign",
                "security.schedule.read",
                "security.schedule.create",
                "security.schedule.update",
                "security.device.read",
                "security.device.approve",
                "security.device.block",
                "security.device.revoke",
                "security.audit.read",
            }
        ),
    ),
    StandardTenantAdminRole(
        role_key="tenant.security_policy_admin",
        role_name="Security Policy Admin",
        description="Tenant Security and retention policy administration",
        permission_keys=frozenset(
            {
                "security.policy.read",
                "security.policy.update",
                "security.retention.read",
                "security.retention.update",
                "security.audit.read",
            }
        ),
    ),
    StandardTenantAdminRole(
        role_key="tenant.security_approver",
        role_name="Security Approver",
        description="Maker-checker approval for privileged access",
        permission_keys=frozenset(
            {
                "security.member.read",
                "security.group.read",
                "security.role.read",
                "security.permission.read",
                "security.privileged_access.approve",
                "security.audit.read",
            }
        ),
    ),
    StandardTenantAdminRole(
        role_key="tenant.auditor",
        role_name="Tenant Auditor",
        description="Read-only Tenant Security audit and review",
        permission_keys=frozenset(
            {
                "security.member.read",
                "security.group.read",
                "security.role.read",
                "security.permission.read",
                "security.location.read",
                "security.schedule.read",
                "security.device.read",
                "security.policy.read",
                "security.retention.read",
                "security.audit.read",
            }
        ),
    ),
)

RESERVED_TENANT_ADMIN_ROLE_KEYS: frozenset[str] = frozenset(
    role.role_key for role in STANDARD_TENANT_ADMIN_ROLES
)


class StandardTenantAdminRoleSeeder:
    """Seed the exact reserved Tenant Admin roles without silently changing existing roles."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def seed(self, *, tenant_id: str, now: datetime) -> bool:
        try:
            if not self._tenant_exists(tenant_id):
                self.s.rollback()
                return False
            self._assert_permission_catalogue()
            for definition in STANDARD_TENANT_ADMIN_ROLES:
                self._seed_or_validate_role(
                    tenant_id=tenant_id,
                    definition=definition,
                    now=now,
                )
            self.s.commit()
            return True
        except Exception:
            self.s.rollback()
            raise

    def _tenant_exists(self, tenant_id: str) -> bool:
        return (
            self.s.execute(
                text("SELECT 1 FROM security.tenants WHERE tenant_id=:tenant_id"),
                {"tenant_id": tenant_id},
            ).first()
            is not None
        )

    def _assert_permission_catalogue(self) -> None:
        rows = self.s.execute(
            text(
                """
                SELECT permission_key,status
                FROM security.permissions
                WHERE module_key='security'
                """
            )
        ).mappings()
        active = {
            str(row["permission_key"])
            for row in rows
            if str(row["status"]) == "ACTIVE"
        }
        missing = SECURITY_ADMIN_PERMISSION_KEYS - active
        if missing:
            raise RuntimeError(
                "Security Admin permission catalogue is incomplete: "
                + ", ".join(sorted(missing))
            )

    def _seed_or_validate_role(
        self,
        *,
        tenant_id: str,
        definition: StandardTenantAdminRole,
        now: datetime,
    ) -> None:
        existing = self.s.execute(
            text(
                """
                SELECT role_id,role_name,description,status
                FROM security.roles
                WHERE tenant_id=:tenant_id AND role_key=:role_key
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "role_key": definition.role_key},
        ).mappings().first()

        if existing is None:
            role_id = str(uuid4())
            self.s.execute(
                text(
                    """
                    INSERT INTO security.roles
                    (role_id,tenant_id,role_key,role_name,description,status,
                     created_at_utc,updated_at_utc)
                    VALUES
                    (:role_id,:tenant_id,:role_key,:role_name,:description,
                     'ACTIVE',:now,:now)
                    """
                ),
                {
                    "role_id": role_id,
                    "tenant_id": tenant_id,
                    "role_key": definition.role_key,
                    "role_name": definition.role_name,
                    "description": definition.description,
                    "now": now,
                },
            )
            self._insert_permissions(
                tenant_id=tenant_id,
                role_id=role_id,
                permission_keys=definition.permission_keys,
                now=now,
            )
            return

        role_id = str(existing["role_id"])
        actual_permissions = frozenset(
            str(value)
            for value in self.s.execute(
                text(
                    """
                    SELECT permission_key
                    FROM security.role_permissions
                    WHERE tenant_id=:tenant_id AND role_id=:role_id
                    """
                ),
                {"tenant_id": tenant_id, "role_id": role_id},
            ).scalars()
        )
        expected_metadata = (
            definition.role_name,
            definition.description,
            "ACTIVE",
        )
        actual_metadata = (
            str(existing["role_name"]),
            existing["description"],
            str(existing["status"]),
        )
        if actual_metadata != expected_metadata or actual_permissions != definition.permission_keys:
            raise RuntimeError(
                f"Reserved Tenant Admin role drift detected: {definition.role_key}"
            )

    def _insert_permissions(
        self,
        *,
        tenant_id: str,
        role_id: str,
        permission_keys: frozenset[str],
        now: datetime,
    ) -> None:
        for permission_key in sorted(permission_keys):
            self.s.execute(
                text(
                    """
                    INSERT INTO security.role_permissions
                    (tenant_id,role_id,permission_key,assigned_at_utc)
                    VALUES (:tenant_id,:role_id,:permission_key,:now)
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "role_id": role_id,
                    "permission_key": permission_key,
                    "now": now,
                },
            )
