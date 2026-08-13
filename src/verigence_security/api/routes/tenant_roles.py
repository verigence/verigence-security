from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from verigence_security.api.dependencies import bearer_token, identity_from_token, repository
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.tenant_rbac_admin import TenantRbacAdminService

router = APIRouter(prefix="/security/v1/admin/tenants/{tenantId}", tags=["Tenant Roles"])


class RoleCreateRequest(BaseModel):
    roleKey: str = Field(min_length=1, max_length=120)
    roleName: str = Field(min_length=1, max_length=180)
    description: str | None = None
    templateKeys: list[str] = Field(default_factory=list)
    permissionKeys: list[str] = Field(default_factory=list)


class RoleUpdateRequest(BaseModel):
    roleName: str | None = Field(default=None, min_length=1, max_length=180)
    description: str | None = None
    status: Literal["ACTIVE", "INACTIVE"] | None = None


class TemplateUpgradeRequest(BaseModel):
    templateKey: str = Field(min_length=1, max_length=180)


def _admin_user(
    token: str,
    settings: Settings,
    repo: SecurityRepository,
    tenant_id: str,
    permission_key: str,
) -> str:
    identity = identity_from_token(token, settings)
    user_id = repo.resolve_identity_user(identity.provider, identity.provider_subject)
    TenantRbacAdminService(repo.s).authorize_user(
        tenant_id=tenant_id,
        user_id=user_id,
        permission_key=permission_key,
    )
    return user_id


def _resolve_template(repo: SecurityRepository, template_key: str) -> dict[str, Any]:
    rows = list(
        repo.s.execute(
            text(
                """
                SELECT t.template_id,t.template_key,t.catalog_version,tp.permission_key
                FROM security.module_role_templates t
                LEFT JOIN security.module_role_template_permissions tp
                  ON tp.template_id=t.template_id
                WHERE t.template_key=:template_key AND t.status='ACTIVE'
                ORDER BY tp.permission_key
                """
            ),
            {"template_key": template_key},
        ).mappings()
    )
    if not rows:
        raise ValueError(f"Template is not ACTIVE: {template_key}")
    return {
        "template_id": str(rows[0]["template_id"]),
        "template_key": str(rows[0]["template_key"]),
        "catalog_version": str(rows[0]["catalog_version"]),
        "permission_keys": [
            str(row["permission_key"])
            for row in rows
            if row["permission_key"] is not None
        ],
    }


def _ensure_permissions_active(
    repo: SecurityRepository,
    permission_keys: set[str],
) -> None:
    for permission_key in sorted(permission_keys):
        row = repo.s.execute(
            text("SELECT status FROM security.permissions WHERE permission_key=:key"),
            {"key": permission_key},
        ).first()
        if row is None or row[0] != "ACTIVE":
            raise ValueError(f"Permission is not ACTIVE: {permission_key}")


def _role_details(
    repo: SecurityRepository,
    tenant_id: str,
    role_id: str,
) -> dict[str, Any]:
    row = repo.s.execute(
        text(
            """
            SELECT role_id,tenant_id,role_key,role_name,description,status,
                   created_at_utc,updated_at_utc
            FROM security.roles
            WHERE tenant_id=:tenant_id AND role_id=:role_id
            """
        ),
        {"tenant_id": tenant_id, "role_id": role_id},
    ).mappings().first()
    if row is None:
        raise LookupError("Role not found")
    permissions = list(
        repo.s.execute(
            text(
                """
                SELECT permission_key FROM security.role_permissions
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                ORDER BY permission_key
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id},
        ).scalars()
    )
    templates = list(
        repo.s.execute(
            text(
                """
                SELECT t.template_key,b.applied_catalog_version
                FROM security.role_template_bindings b
                JOIN security.module_role_templates t ON t.template_id=b.template_id
                WHERE b.tenant_id=:tenant_id AND b.role_id=:role_id
                  AND b.status='CURRENT'
                ORDER BY t.template_key
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id},
        ).mappings()
    )
    result = dict(row)
    result["permission_keys"] = [str(value) for value in permissions]
    result["templates"] = [dict(value) for value in templates]
    return result


def _create_role(
    repo: SecurityRepository,
    tenant_id: str,
    body: RoleCreateRequest,
    actor_id: str,
    correlation_id: str,
) -> dict[str, Any]:
    if body.roleKey.startswith("platform.") or body.roleKey.startswith("tenant."):
        raise ValueError("Reserved role key")
    templates = [_resolve_template(repo, key) for key in body.templateKeys]
    permission_keys = set(body.permissionKeys)
    for template in templates:
        permission_keys.update(template["permission_keys"])
    _ensure_permissions_active(repo, permission_keys)
    now = datetime.now(UTC)
    role_id = str(uuid4())
    try:
        repo.s.execute(
            text(
                """
                INSERT INTO security.roles
                (role_id,tenant_id,role_key,role_name,description,status,
                 created_at_utc,updated_at_utc)
                VALUES (:role_id,:tenant_id,:role_key,:role_name,:description,
                        'ACTIVE',:now,:now)
                """
            ),
            {
                "role_id": role_id,
                "tenant_id": tenant_id,
                "role_key": body.roleKey,
                "role_name": body.roleName,
                "description": body.description,
                "now": now,
            },
        )
        for permission_key in sorted(permission_keys):
            repo.s.execute(
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
        for template in templates:
            repo.s.execute(
                text(
                    """
                    INSERT INTO security.role_template_bindings
                    (binding_id,tenant_id,role_id,template_id,applied_catalog_version,
                     status,applied_by_user_id,applied_at_utc)
                    VALUES (:id,:tenant_id,:role_id,:template_id,:catalog_version,
                            'CURRENT',:actor_id,:now)
                    """
                ),
                {
                    "id": str(uuid4()),
                    "tenant_id": tenant_id,
                    "role_id": role_id,
                    "template_id": template["template_id"],
                    "catalog_version": template["catalog_version"],
                    "actor_id": actor_id,
                    "now": now,
                },
            )
        repo.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,occurred_at_utc)
                VALUES (:id,:correlation_id,'TENANT',:tenant_id,:actor_id,
                        'security.role.create','ROLE',:role_id,'SUCCESS',:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "role_id": role_id,
                "now": now,
            },
        )
        repo.s.commit()
    except Exception:
        repo.s.rollback()
        raise
    return _role_details(repo, tenant_id, role_id)


def _effective_role_users(
    repo: SecurityRepository,
    tenant_id: str,
    role_id: str,
    now: datetime,
) -> list[str]:
    rows = repo.s.execute(
        text(
            """
            SELECT DISTINCT user_id FROM (
                SELECT user_id FROM security.user_role_assignments
                WHERE tenant_id=:tenant_id AND role_id=:role_id AND status='ACTIVE'
                  AND (valid_from_utc IS NULL OR valid_from_utc<=:now)
                  AND (valid_to_utc IS NULL OR valid_to_utc>:now)
                UNION
                SELECT gm.user_id
                FROM security.group_role_assignments gra
                JOIN security.groups g
                  ON g.tenant_id=gra.tenant_id AND g.group_id=gra.group_id
                 AND g.status='ACTIVE'
                JOIN security.group_memberships gm
                  ON gm.tenant_id=g.tenant_id AND gm.group_id=g.group_id
                 AND gm.status='ACTIVE'
                WHERE gra.tenant_id=:tenant_id AND gra.role_id=:role_id
                  AND gra.status='ACTIVE'
                  AND (gm.valid_from_utc IS NULL OR gm.valid_from_utc<=:now)
                  AND (gm.valid_to_utc IS NULL OR gm.valid_to_utc>:now)
            ) role_users
            """
        ),
        {"tenant_id": tenant_id, "role_id": role_id, "now": now},
    ).scalars()
    return [str(value) for value in rows]


def _upgrade_template(
    repo: SecurityRepository,
    tenant_id: str,
    role_id: str,
    template_key: str,
    actor_id: str,
    correlation_id: str,
) -> dict[str, Any]:
    template = _resolve_template(repo, template_key)
    _ensure_permissions_active(repo, set(template["permission_keys"]))
    now = datetime.now(UTC)
    affected_users = _effective_role_users(repo, tenant_id, role_id, now)
    try:
        role = repo.s.execute(
            text(
                """
                SELECT 1 FROM security.roles
                WHERE tenant_id=:tenant_id AND role_id=:role_id AND status='ACTIVE'
                FOR UPDATE
                """
            ),
            {"tenant_id": tenant_id, "role_id": role_id},
        ).first()
        if role is None:
            raise LookupError("Role not found or inactive")
        for permission_key in template["permission_keys"]:
            repo.s.execute(
                text(
                    """
                    INSERT INTO security.role_permissions
                    (tenant_id,role_id,permission_key,assigned_at_utc)
                    VALUES (:tenant_id,:role_id,:permission_key,:now)
                    ON CONFLICT (tenant_id,role_id,permission_key) DO NOTHING
                    """
                ),
                {
                    "tenant_id": tenant_id,
                    "role_id": role_id,
                    "permission_key": permission_key,
                    "now": now,
                },
            )
        repo.s.execute(
            text(
                """
                UPDATE security.role_template_bindings
                SET status='SUPERSEDED',superseded_at_utc=:now
                WHERE tenant_id=:tenant_id AND role_id=:role_id
                  AND template_id=:template_id AND status='CURRENT'
                """
            ),
            {
                "tenant_id": tenant_id,
                "role_id": role_id,
                "template_id": template["template_id"],
                "now": now,
            },
        )
        repo.s.execute(
            text(
                """
                INSERT INTO security.role_template_bindings
                (binding_id,tenant_id,role_id,template_id,applied_catalog_version,
                 status,applied_by_user_id,applied_at_utc)
                VALUES (:id,:tenant_id,:role_id,:template_id,:catalog_version,
                        'CURRENT',:actor_id,:now)
                """
            ),
            {
                "id": str(uuid4()),
                "tenant_id": tenant_id,
                "role_id": role_id,
                "template_id": template["template_id"],
                "catalog_version": template["catalog_version"],
                "actor_id": actor_id,
                "now": now,
            },
        )
        for user_id in sorted(set(affected_users)):
            repo.s.execute(
                text(
                    """
                    UPDATE security.tenant_memberships
                    SET authorization_version=authorization_version+1,updated_at_utc=:now
                    WHERE tenant_id=:tenant_id AND user_id=:user_id AND status='ACTIVE'
                    """
                ),
                {"tenant_id": tenant_id, "user_id": user_id, "now": now},
            )
        repo.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,occurred_at_utc)
                VALUES (:id,:correlation_id,'TENANT',:tenant_id,:actor_id,
                        'security.role.template.upgrade','ROLE',:resource_id,'SUCCESS',:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "resource_id": f"{role_id}:{template_key}",
                "now": now,
            },
        )
        repo.s.commit()
    except Exception:
        repo.s.rollback()
        raise
    return _role_details(repo, tenant_id, role_id)


@router.get("/roles")
def list_roles(
    tenantId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _admin_user(token, settings, repo, tenantId, "security.role.read")
    return TenantRbacAdminService(repo.s).list_roles(tenantId)


@router.post("/roles", status_code=status.HTTP_201_CREATED)
def create_role(
    tenantId: str,
    body: RoleCreateRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.create")
    try:
        return _create_role(
            repo,
            tenantId,
            body,
            actor_id,
            request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/roles/{roleId}")
def get_role(
    tenantId: str,
    roleId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    _admin_user(token, settings, repo, tenantId, "security.role.read")
    try:
        return _role_details(repo, tenantId, roleId)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.patch("/roles/{roleId}")
def update_role(
    tenantId: str,
    roleId: str,
    body: RoleUpdateRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.update")
    row = TenantRbacAdminService(repo.s).update_role(
        tenant_id=tenantId,
        role_id=roleId,
        actor_user_id=actor_id,
        correlation_id=request.state.correlation_id,
        role_name=body.roleName,
        description=body.description,
        status=body.status,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return _role_details(repo, tenantId, roleId)


@router.put(
    "/roles/{roleId}/permissions/{permissionKey}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def add_role_permission(
    tenantId: str,
    roleId: str,
    permissionKey: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.update")
    try:
        TenantRbacAdminService(repo.s).add_role_permission(
            tenant_id=tenantId,
            role_id=roleId,
            permission_key=permissionKey,
            actor_user_id=actor_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/roles/{roleId}/permissions/{permissionKey}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_role_permission(
    tenantId: str,
    roleId: str,
    permissionKey: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.update")
    TenantRbacAdminService(repo.s).remove_role_permission(
        tenant_id=tenantId,
        role_id=roleId,
        permission_key=permissionKey,
        actor_user_id=actor_id,
        correlation_id=request.state.correlation_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put(
    "/members/{userId}/roles/{roleId}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def assign_user_role(
    tenantId: str,
    userId: str,
    roleId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.assign")
    try:
        TenantRbacAdminService(repo.s).assign_user_role(
            tenant_id=tenantId,
            user_id=userId,
            role_id=roleId,
            actor_user_id=actor_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete(
    "/members/{userId}/roles/{roleId}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_user_role(
    tenantId: str,
    userId: str,
    roleId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.assign")
    TenantRbacAdminService(repo.s).remove_user_role(
        tenant_id=tenantId,
        user_id=userId,
        role_id=roleId,
        actor_user_id=actor_id,
        correlation_id=request.state.correlation_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/roles/{roleId}/template-upgrades")
def upgrade_role_template(
    tenantId: str,
    roleId: str,
    body: TemplateUpgradeRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.role.update")
    try:
        return _upgrade_template(
            repo,
            tenantId,
            roleId,
            body.templateKey,
            actor_id,
            request.state.correlation_id,
        )
    except (LookupError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/permissions")
def list_permissions(
    tenantId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _admin_user(token, settings, repo, tenantId, "security.permission.read")
    return TenantRbacAdminService(repo.s).list_permissions()


@router.get("/module-role-templates")
def list_templates(
    tenantId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _admin_user(token, settings, repo, tenantId, "security.permission.read")
    return TenantRbacAdminService(repo.s).list_templates()
