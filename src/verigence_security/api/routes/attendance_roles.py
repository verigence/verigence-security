from __future__ import annotations

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
    "/users/{userId}/module-roles/attendance/HRADMIN",
    response_model=AttendanceRoleMutationResponse,
)
def assign_hradmin(
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AttendanceRoleMutationResponse:
    """Assign global Attendance HRADMIN without Tenant/Project scope."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = AttendanceModuleRoleService(session).assign(
            user_id=userId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return AttendanceRoleMutationResponse(
        userId=userId,
        changed=changed,
        assignmentId=assignment_id,
    )


@router.delete(
    "/users/{userId}/module-roles/attendance/HRADMIN",
    response_model=AttendanceRoleMutationResponse,
)
def remove_hradmin(
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AttendanceRoleMutationResponse:
    """Remove global Attendance HRADMIN without touching operating roles."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = AttendanceModuleRoleService(session).remove(
            user_id=userId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return AttendanceRoleMutationResponse(
        userId=userId,
        changed=changed,
        assignmentId=assignment_id,
    )
