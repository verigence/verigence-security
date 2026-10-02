from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.attendance_finance_role_schemas import (
    AttendanceFinanceRoleMutationResponse,
)
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.attendance_financeadmin_role import (
    AttendanceFinanceAdminRoleService,
)
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Attendance Finance Role"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


@router.put(
    "/users/{userId}/module-roles/attendance/FINANCEADMIN",
    response_model=AttendanceFinanceRoleMutationResponse,
)
def assign_financeadmin(
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AttendanceFinanceRoleMutationResponse:
    """Assign Attendance-only FINANCEADMIN without changing any existing USER role."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = AttendanceFinanceAdminRoleService(session).assign(
            user_id=userId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return AttendanceFinanceRoleMutationResponse(
        userId=userId,
        changed=changed,
        assignmentId=assignment_id,
    )


@router.delete(
    "/users/{userId}/module-roles/attendance/FINANCEADMIN",
    response_model=AttendanceFinanceRoleMutationResponse,
)
def remove_financeadmin(
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AttendanceFinanceRoleMutationResponse:
    """Remove Attendance-only FINANCEADMIN without changing any existing USER role."""
    _require_super_admin(actor)
    try:
        changed, assignment_id = AttendanceFinanceAdminRoleService(session).remove(
            user_id=userId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return AttendanceFinanceRoleMutationResponse(
        userId=userId,
        changed=changed,
        assignmentId=assignment_id,
    )
