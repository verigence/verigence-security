from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from verigence_security.api.dependencies import (
    bearer_token,
    identity_from_token,
    repository,
)
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.tenant_rbac_admin import TenantRbacAdminService

router = APIRouter(prefix="/security/v1/admin/tenants/{tenantId}/groups", tags=["Tenant Groups"])


class GroupCreateRequest(BaseModel):
    groupKey: str = Field(min_length=1, max_length=120)
    groupName: str = Field(min_length=1, max_length=240)
    description: str | None = None


class GroupUpdateRequest(BaseModel):
    groupName: str | None = Field(default=None, min_length=1, max_length=240)
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


@router.get("")
def list_groups(
    tenantId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> list[dict[str, object]]:
    _admin_user(token, settings, repo, tenantId, "security.group.read")
    return TenantRbacAdminService(repo.s).list_groups(tenantId)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_group(
    tenantId: str,
    body: GroupCreateRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    user_id = _admin_user(token, settings, repo, tenantId, "security.group.create")
    try:
        return TenantRbacAdminService(repo.s).create_group(
            tenant_id=tenantId,
            group_key=body.groupKey,
            group_name=body.groupName,
            description=body.description,
            actor_user_id=user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{groupId}")
def get_group(
    tenantId: str,
    groupId: str,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    _admin_user(token, settings, repo, tenantId, "security.group.read")
    row = TenantRbacAdminService(repo.s).get_group(tenantId, groupId)
    if row is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return row


@router.patch("/{groupId}")
def update_group(
    tenantId: str,
    groupId: str,
    body: GroupUpdateRequest,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> dict[str, object]:
    user_id = _admin_user(token, settings, repo, tenantId, "security.group.update")
    row = TenantRbacAdminService(repo.s).update_group(
        tenant_id=tenantId,
        group_id=groupId,
        actor_user_id=user_id,
        correlation_id=request.state.correlation_id,
        group_name=body.groupName,
        description=body.description,
        status=body.status,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Group not found")
    return row


@router.put("/{groupId}/members/{userId}", status_code=status.HTTP_204_NO_CONTENT)
def add_group_member(
    tenantId: str,
    groupId: str,
    userId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.group.assign")
    try:
        TenantRbacAdminService(repo.s).add_group_member(
            tenant_id=tenantId,
            group_id=groupId,
            user_id=userId,
            actor_user_id=actor_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{groupId}/members/{userId}", status_code=status.HTTP_204_NO_CONTENT)
def remove_group_member(
    tenantId: str,
    groupId: str,
    userId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.group.assign")
    TenantRbacAdminService(repo.s).remove_group_member(
        tenant_id=tenantId,
        group_id=groupId,
        user_id=userId,
        actor_user_id=actor_id,
        correlation_id=request.state.correlation_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.put("/{groupId}/roles/{roleId}", status_code=status.HTTP_204_NO_CONTENT)
def assign_group_role(
    tenantId: str,
    groupId: str,
    roleId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.group.assign")
    try:
        TenantRbacAdminService(repo.s).assign_group_role(
            tenant_id=tenantId,
            group_id=groupId,
            role_id=roleId,
            actor_user_id=actor_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/{groupId}/roles/{roleId}", status_code=status.HTTP_204_NO_CONTENT)
def remove_group_role(
    tenantId: str,
    groupId: str,
    roleId: str,
    request: Request,
    token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    actor_id = _admin_user(token, settings, repo, tenantId, "security.group.assign")
    TenantRbacAdminService(repo.s).remove_group_role(
        tenant_id=tenantId,
        group_id=groupId,
        role_id=roleId,
        actor_user_id=actor_id,
        correlation_id=request.state.correlation_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
