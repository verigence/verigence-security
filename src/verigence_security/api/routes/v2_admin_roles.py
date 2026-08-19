from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_admin_role_schemas import AdminRoleMutationResponse
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.v2_admin_role_mutations import (
    AuditedAdminRoleAssignmentService,
)
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1", tags=["Security v2 Admin Roles"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


def _response(
    *,
    user_id: str,
    role_key: str,
    scope_type: str,
    scope_id: str,
    result: object,
) -> AdminRoleMutationResponse:
    return AdminRoleMutationResponse(
        userId=user_id,
        roleKey=role_key,  # type: ignore[arg-type]
        scopeType=scope_type,  # type: ignore[arg-type]
        scopeId=scope_id,
        changed=bool(getattr(result, "changed")),
        assignmentId=(
            str(getattr(result, "assignment_id"))
            if getattr(result, "assignment_id") is not None
            else None
        ),
    )


@router.put(
    "/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin",
    response_model=AdminRoleMutationResponse,
)
def assign_tenant_admin(
    tenantId: str,
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AdminRoleMutationResponse:
    _require_super_admin(actor)
    try:
        result = AuditedAdminRoleAssignmentService(session).assign(
            user_id=userId,
            role_key="TenantAdmin",
            scope_id=tenantId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _response(
        user_id=userId,
        role_key="TenantAdmin",
        scope_type="TENANT",
        scope_id=tenantId,
        result=result,
    )


@router.delete(
    "/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin",
    response_model=AdminRoleMutationResponse,
)
def remove_tenant_admin(
    tenantId: str,
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AdminRoleMutationResponse:
    _require_super_admin(actor)
    try:
        result = AuditedAdminRoleAssignmentService(session).remove(
            user_id=userId,
            role_key="TenantAdmin",
            scope_id=tenantId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _response(
        user_id=userId,
        role_key="TenantAdmin",
        scope_type="TENANT",
        scope_id=tenantId,
        result=result,
    )


@router.put(
    "/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin",
    response_model=AdminRoleMutationResponse,
)
def assign_module_admin(
    moduleKey: str,
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AdminRoleMutationResponse:
    _require_super_admin(actor)
    try:
        result = AuditedAdminRoleAssignmentService(session).assign(
            user_id=userId,
            role_key="ModuleAdmin",
            scope_id=moduleKey.lower(),
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _response(
        user_id=userId,
        role_key="ModuleAdmin",
        scope_type="MODULE",
        scope_id=moduleKey.lower(),
        result=result,
    )


@router.delete(
    "/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin",
    response_model=AdminRoleMutationResponse,
)
def remove_module_admin(
    moduleKey: str,
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> AdminRoleMutationResponse:
    _require_super_admin(actor)
    try:
        result = AuditedAdminRoleAssignmentService(session).remove(
            user_id=userId,
            role_key="ModuleAdmin",
            scope_id=moduleKey.lower(),
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _response(
        user_id=userId,
        role_key="ModuleAdmin",
        scope_type="MODULE",
        scope_id=moduleKey.lower(),
        result=result,
    )
