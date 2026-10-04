from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.hr_role_schemas import HrRoleMutationResponse, HrRolesResponse
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.hr_module_roles import HrModuleRoleService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["HR Roles"])

HrRoleKey = Literal["HRADMIN", "FINANCEADMIN", "CEO"]


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.get("/users/{userId}/module-roles/hr", response_model=HrRolesResponse)
def list_hr_roles(
    userId: str,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> HrRolesResponse:
    """The HR roles a person holds now. SuperAdmin only."""
    _require_super_admin(actor)
    try:
        roles = HrModuleRoleService(session).list_roles(user_id=userId)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return HrRolesResponse(userId=userId, roles=roles)


@router.put("/users/{userId}/module-roles/hr/{roleKey}", response_model=HrRoleMutationResponse)
def assign_hr_role(
    userId: str,
    roleKey: HrRoleKey,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> HrRoleMutationResponse:
    """Assign a company-wide HR role (HRADMIN, FINANCEADMIN or CEO). SuperAdmin only."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = HrModuleRoleService(session).assign(
            user_id=userId,
            role_key=roleKey,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return HrRoleMutationResponse(userId=userId, roleKey=roleKey, changed=changed, assignmentId=assignment_id)


@router.delete("/users/{userId}/module-roles/hr/{roleKey}", response_model=HrRoleMutationResponse)
def remove_hr_role(
    userId: str,
    roleKey: HrRoleKey,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> HrRoleMutationResponse:
    """Remove a company-wide HR role. SuperAdmin only."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = HrModuleRoleService(session).remove(
            user_id=userId,
            role_key=roleKey,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return HrRoleMutationResponse(userId=userId, roleKey=roleKey, changed=changed, assignmentId=assignment_id)
