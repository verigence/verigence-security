from __future__ import annotations

import json
from datetime import datetime
from uuid import uuid4

from sqlalchemy import text

from verigence_security.services.admin_control_plane_catalog import STANDARD_TENANT_ADMIN_ROLES
from verigence_security.services.platform_admin import PlatformTenantService as BasePlatformTenantService


class PlatformTenantService(BasePlatformTenantService):
    """Runtime tenant service with bulk role/permission seeding.

    Project creation provisions more than 150 v2 operating-role permissions plus the
    temporary legacy tenant-admin role bundle. The original implementation executed
    one INSERT per permission, which turns into hundreds of network round-trips against
    the remote DEV PostgreSQL service. Keep the same transaction and data contract, but
    seed each catalogue with set-based SQL so tenant creation remains comfortably inside
    the Project Administration request budget.
    """

    def _seed_v2_tenant_role_defaults(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        now: datetime,
    ) -> None:
        summary = self.s.execute(
            text(
                """
                SELECT count(*) AS permission_count,
                       count(DISTINCT d.role_key) AS role_count
                FROM security.platform_role_permission_defaults d
                JOIN security.permissions p
                  ON p.permission_key=d.permission_key
                 AND p.status='ACTIVE'
                WHERE d.status='ACTIVE'
                  AND d.role_key IN ('PC','TL','PM','CRM','Executive')
                """
            )
        ).mappings().one()
        if int(summary["role_count"]) != 5 or int(summary["permission_count"]) <= 0:
            raise RuntimeError("Approved v2 operating-role platform defaults are not ready")

        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_role_permissions
                (tenant_id,role_key,permission_key,assigned_by_user_id,assigned_at_utc)
                SELECT :tenant_id,d.role_key,d.permission_key,:actor_user_id,:now
                FROM security.platform_role_permission_defaults d
                JOIN security.permissions p
                  ON p.permission_key=d.permission_key
                 AND p.status='ACTIVE'
                WHERE d.status='ACTIVE'
                  AND d.role_key IN ('PC','TL','PM','CRM','Executive')
                ORDER BY d.role_key,d.permission_key
                """
            ),
            {
                "tenant_id": tenant_id,
                "actor_user_id": actor_user_id,
                "now": now,
            },
        )

    def _seed_standard_tenant_roles(self, *, tenant_id: str, now: datetime) -> None:
        role_rows: list[dict[str, object]] = []
        permission_rows: list[dict[str, str]] = []
        for definition in STANDARD_TENANT_ADMIN_ROLES:
            role_id = str(uuid4())
            role_rows.append(
                {
                    "role_id": role_id,
                    "role_key": definition.role_key,
                    "role_name": definition.role_name,
                    "description": definition.description,
                }
            )
            permission_rows.extend(
                {"role_id": role_id, "permission_key": permission_key}
                for permission_key in sorted(definition.permission_keys)
            )

        self.s.execute(
            text(
                """
                INSERT INTO security.roles
                (role_id,tenant_id,role_key,role_name,description,status,
                 created_at_utc,updated_at_utc)
                SELECT x.role_id::uuid,:tenant_id,x.role_key,x.role_name,x.description,
                       'ACTIVE',:now,:now
                FROM jsonb_to_recordset(CAST(:rows_json AS jsonb))
                     AS x(role_id text,role_key text,role_name text,description text)
                """
            ),
            {
                "tenant_id": tenant_id,
                "rows_json": json.dumps(role_rows),
                "now": now,
            },
        )

        self.s.execute(
            text(
                """
                INSERT INTO security.role_permissions
                (tenant_id,role_id,permission_key,assigned_at_utc)
                SELECT :tenant_id,x.role_id::uuid,x.permission_key,:now
                FROM jsonb_to_recordset(CAST(:rows_json AS jsonb))
                     AS x(role_id text,permission_key text)
                """
            ),
            {
                "tenant_id": tenant_id,
                "rows_json": json.dumps(permission_rows),
                "now": now,
            },
        )
