from __future__ import annotations

import re
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.core.errors import security_error

_PERMISSION = re.compile(r"^[a-z0-9]+(\.[a-z0-9_-]+){2,}$")


def is_canonical_permission(value: str) -> bool:
    return bool(_PERMISSION.fullmatch(value)) and ":" not in value


def validate_permissions(values: list[str]) -> list[str]:
    invalid = [p for p in values if not is_canonical_permission(p)]
    if invalid:
        raise ValueError(f"Invalid canonical permission(s): {', '.join(invalid)}")
    return sorted(set(values))


def effective_user_permissions(
    session: Session,
    tenant_id: str,
    user_id: str,
    now: datetime,
) -> tuple[list[str], list[str]]:
    rows = session.execute(
        text(
            """
            WITH effective_roles AS (
                SELECT r.tenant_id,r.role_id,r.role_key
                FROM security.user_role_assignments ura
                JOIN security.roles r
                  ON r.tenant_id=ura.tenant_id
                 AND r.role_id=ura.role_id
                 AND r.status='ACTIVE'
                WHERE ura.tenant_id=:tenant_id
                  AND ura.user_id=:user_id
                  AND ura.status='ACTIVE'
                  AND (ura.valid_from_utc IS NULL OR ura.valid_from_utc<=:now)
                  AND (ura.valid_to_utc IS NULL OR ura.valid_to_utc>:now)
                UNION
                SELECT r.tenant_id,r.role_id,r.role_key
                FROM security.group_memberships gm
                JOIN security.groups g
                  ON g.tenant_id=gm.tenant_id
                 AND g.group_id=gm.group_id
                 AND g.status='ACTIVE'
                JOIN security.group_role_assignments gra
                  ON gra.tenant_id=g.tenant_id
                 AND gra.group_id=g.group_id
                 AND gra.status='ACTIVE'
                JOIN security.roles r
                  ON r.tenant_id=gra.tenant_id
                 AND r.role_id=gra.role_id
                 AND r.status='ACTIVE'
                WHERE gm.tenant_id=:tenant_id
                  AND gm.user_id=:user_id
                  AND gm.status='ACTIVE'
                  AND (gm.valid_from_utc IS NULL OR gm.valid_from_utc<=:now)
                  AND (gm.valid_to_utc IS NULL OR gm.valid_to_utc>:now)
            )
            SELECT DISTINCT er.role_key,p.permission_key
            FROM effective_roles er
            JOIN security.role_permissions rp
              ON rp.tenant_id=er.tenant_id AND rp.role_id=er.role_id
            JOIN security.permissions p
              ON p.permission_key=rp.permission_key AND p.status='ACTIVE'
            """
        ),
        {"tenant_id": tenant_id, "user_id": user_id, "now": now},
    ).mappings().all()
    roles = sorted({str(row["role_key"]) for row in rows})
    permissions = sorted({str(row["permission_key"]) for row in rows})
    if not permissions:
        raise security_error("ROLE_REQUIRED")
    return roles, permissions
