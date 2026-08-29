from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.attendance_role_schemas import AttendanceRoleMutationResponse
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.attendance_module_roles import AttendanceModuleRoleService
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Attendance Roles"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.put(
    "/tenants/{tenantId}/users/{userId}/module-roles/attendance/HRADMIN",
    response_model=AttendanceRoleMutationResponse,
)
def assign_hradmin(
    tenantId: UUID,
    userId: UUID,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AttendanceRoleMutationResponse:
    """Assign tenant-scoped Attendance HRADMIN without changing operating role."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = AttendanceModuleRoleService(session).assign(
            tenant_id=str(tenantId),
            user_id=str(userId),
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return AttendanceRoleMutationResponse(
        tenantId=tenantId,
        userId=userId,
        changed=changed,
        assignmentId=UUID(assignment_id),
    )


@router.delete(
    "/tenants/{tenantId}/users/{userId}/module-roles/attendance/HRADMIN",
    response_model=AttendanceRoleMutationResponse,
)
def remove_hradmin(
    tenantId: UUID,
    userId: UUID,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AttendanceRoleMutationResponse:
    """Remove tenant-scoped HRADMIN without touching the user's operating role."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = AttendanceModuleRoleService(session).remove(
            tenant_id=str(tenantId),
            user_id=str(userId),
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return AttendanceRoleMutationResponse(
        tenantId=tenantId,
        userId=userId,
        changed=changed,
        assignmentId=UUID(assignment_id) if assignment_id is not None else None,
    )
