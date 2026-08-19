from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_group_schemas import (
    RoleAlignedGroupResponse,
    RoleAlignedGroupUserResponse,
)
from verigence_security.api.v2_human_dependencies import clerk_human_actor
from verigence_security.api.v2_rbac_schemas import OperatingRoleKey
from verigence_security.core.errors import security_error
from verigence_security.services.v2_human_actor import HumanActorContext
from verigence_security.services.v2_role_groups import RoleAlignedGroupService

router = APIRouter(prefix="/security/v1/tenants/{tenantId}/groups", tags=["Security v2 Groups"])


def _require_group_read(actor: HumanActorContext, tenant_id: str) -> None:
    if actor.is_super_admin or actor.is_tenant_admin(tenant_id):
        return
    raise security_error("PERMISSION_DENIED")


def _group_response(tenant_id: str, row: dict[str, object]) -> RoleAlignedGroupResponse:
    return RoleAlignedGroupResponse(
        tenantId=tenant_id,
        roleKey=cast(OperatingRoleKey, str(row["role_key"])),
        displayName=str(row["display_name"]),
        memberCount=int(row["member_count"]),
    )


@router.get("", response_model=list[RoleAlignedGroupResponse])
def list_role_groups(
    tenantId: str,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> list[RoleAlignedGroupResponse]:
    _require_group_read(actor, tenantId)
    service = RoleAlignedGroupService(session)
    if not service.tenant_exists(tenantId):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return [_group_response(tenantId, row) for row in service.list_groups(tenantId)]


@router.get("/{roleKey}", response_model=RoleAlignedGroupResponse)
def get_role_group(
    tenantId: str,
    roleKey: str,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> RoleAlignedGroupResponse:
    _require_group_read(actor, tenantId)
    service = RoleAlignedGroupService(session)
    if not service.tenant_exists(tenantId):
        raise HTTPException(status_code=404, detail="Tenant not found")
    row = service.group(tenantId, roleKey)
    if row is None:
        raise HTTPException(status_code=404, detail="Role-aligned Group not found")
    return _group_response(tenantId, row)


@router.get("/{roleKey}/users", response_model=list[RoleAlignedGroupUserResponse])
def list_role_group_users(
    tenantId: str,
    roleKey: str,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> list[RoleAlignedGroupUserResponse]:
    _require_group_read(actor, tenantId)
    service = RoleAlignedGroupService(session)
    if not service.tenant_exists(tenantId):
        raise HTTPException(status_code=404, detail="Tenant not found")
    if service.group(tenantId, roleKey) is None:
        raise HTTPException(status_code=404, detail="Role-aligned Group not found")
    return [
        RoleAlignedGroupUserResponse(
            userId=str(row["user_id"]),
            displayName=str(row["display_name"]),
            primaryEmail=(str(row["primary_email"]) if row["primary_email"] is not None else None),
            status=str(row["status"]),
        )
        for row in service.users(tenantId, roleKey)
    ]
