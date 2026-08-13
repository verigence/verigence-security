from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from verigence_security.api.dependencies import bearer_token, identity_from_token, repository
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.tenant_rbac_admin import TenantRbacAdminService

router = APIRouter(prefix="/security/v1/admin/tenants/{tenantId}", tags=["Tenant Roles"])


class RoleCreateRequest(BaseModel):
    roleKey: str = Field(min_length=1, max_length=120)
    roleName: str = Field(min_length=1, max_length=180)
    description: str | None = None
    permissionKeys: list[str] = Field(default_factory=list)


class RoleUpdateRequest(BaseModel):
    roleName: str | None = Field(default=None, min_length=1, max_length=180)
    description: str | None = None
    status: str | None = None


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
        return TenantRbacAdminService(repo.s).create_role(
            tenant_id=tenantId,
            role_key=body.roleKey,
            role_name=body.roleName,
            description=body.description,
            permission_keys=tuple(body.permissionKeys),
            actor_user_id=actor_id,
            correlation_id=request.state.correlation_id,
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
    row = TenantRbacAdminService(repo.s).get_role(tenantId, roleId)
    if row is None:
        raise HTTPException(status_code=404, detail="Role not found")
    return row


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
    return row


@router.put("/roles/{roleId}/permissions/{permissionKey}", status_code=status.HTTP_204_NO_CONTENT)
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


@router.delete("/roles/{roleId}/permissions/{permissionKey}", status_code=status.HTTP_204_NO_CONTENT)
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


@router.put("/members/{userId}/roles/{roleId}", status_code=status.HTTP_204_NO_CONTENT)
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


@router.delete("/members/{userId}/roles/{roleId}", status_code=status.HTTP_204_NO_CONTENT)
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
