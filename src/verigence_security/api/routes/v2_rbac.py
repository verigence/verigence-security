from __future__ import annotations

from typing import cast

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.v2_human_dependencies import clerk_human_actor
from verigence_security.api.v2_rbac_schemas import (
    OperatingRoleKey,
    OperatingRoleMutationResponse,
    OperatingRolePutRequest,
    RoleDefinitionResponse,
    RolePermissionBundleResponse,
    TenantRolePermissionBundlePutRequest,
    TenantRolePermissionBundleResponse,
)
from verigence_security.core.errors import security_error
from verigence_security.services.v2_human_actor import HumanActorContext
from verigence_security.services.v2_rbac import (
    OperatingRoleAssignmentService,
    RoleDefinitionService,
    TenantRoleBundleService,
)

router = APIRouter(prefix="/security/v1", tags=["Security v2 RBAC"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


def _require_tenant_role_admin(actor: HumanActorContext, tenant_id: str) -> None:
    if not actor.is_super_admin and not actor.is_tenant_admin(tenant_id):
        raise security_error("PERMISSION_DENIED")


def _require_tenant_exists(session: Session, tenant_id: str) -> None:
    exists = session.execute(
        text("SELECT 1 FROM security.tenants WHERE tenant_id=:tenant_id"),
        {"tenant_id": tenant_id},
    ).first()
    if exists is None:
        raise HTTPException(status_code=404, detail="Tenant not found")


def _role_response(row: dict[str, object]) -> RoleDefinitionResponse:
    return RoleDefinitionResponse(
        roleKey=str(row["role_key"]),
        roleClass=cast(str, row["role_class"]),
        displayName=str(row["display_name"]),
        status=cast(str, row["status"]),
    )


def _operating_result_response(
    *,
    tenant_id: str,
    user_id: str,
    result: object,
) -> OperatingRoleMutationResponse:
    changed = bool(getattr(result, "changed"))
    assignment_id = getattr(result, "assignment_id")
    role_key = getattr(result, "role_key")
    return OperatingRoleMutationResponse(
        tenantId=tenant_id,
        userId=user_id,
        changed=changed,
        assignmentId=str(assignment_id) if assignment_id is not None else None,
        roleKey=cast(OperatingRoleKey | None, role_key),
    )


@router.get("/roles", response_model=list[RoleDefinitionResponse])
def list_v2_roles(
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> list[RoleDefinitionResponse]:
    # Role definitions are catalogue metadata. Authentication still requires an
    # ACTIVE Clerk-backed human USER; no machine actor can enter this route.
    _ = actor
    return [_role_response(row) for row in RoleDefinitionService(session).list_roles()]


@router.get(
    "/platform/role-defaults/{roleKey}",
    response_model=RolePermissionBundleResponse,
)
def get_platform_role_default(
    roleKey: str,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> RolePermissionBundleResponse:
    _require_super_admin(actor)
    try:
        permissions = TenantRoleBundleService(session).platform_default(roleKey)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RolePermissionBundleResponse(
        roleKey=cast(OperatingRoleKey, roleKey),
        permissions=permissions,
    )


@router.get(
    "/tenants/{tenantId}/role-bundles/{roleKey}",
    response_model=TenantRolePermissionBundleResponse,
)
def get_tenant_role_bundle(
    tenantId: str,
    roleKey: str,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> TenantRolePermissionBundleResponse:
    _require_tenant_role_admin(actor, tenantId)
    _require_tenant_exists(session, tenantId)
    try:
        permissions = TenantRoleBundleService(session).tenant_bundle(tenantId, roleKey)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return TenantRolePermissionBundleResponse(
        tenantId=tenantId,
        roleKey=cast(OperatingRoleKey, roleKey),
        permissions=permissions,
    )


@router.put(
    "/tenants/{tenantId}/role-bundles/{roleKey}",
    response_model=TenantRolePermissionBundleResponse,
)
def replace_tenant_role_bundle(
    tenantId: str,
    roleKey: str,
    body: TenantRolePermissionBundlePutRequest,
    request: Request,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> TenantRolePermissionBundleResponse:
    _require_super_admin(actor)
    try:
        permissions = TenantRoleBundleService(session).replace_tenant_bundle(
            tenant_id=tenantId,
            role_key=roleKey,
            permission_keys=body.permissions,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return TenantRolePermissionBundleResponse(
        tenantId=tenantId,
        roleKey=cast(OperatingRoleKey, roleKey),
        permissions=permissions,
    )


@router.put(
    "/tenants/{tenantId}/users/{userId}/operating-role",
    response_model=OperatingRoleMutationResponse,
)
def set_operating_role(
    tenantId: str,
    userId: str,
    body: OperatingRolePutRequest,
    request: Request,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> OperatingRoleMutationResponse:
    _require_tenant_role_admin(actor, tenantId)
    try:
        result = OperatingRoleAssignmentService(session).set_role(
            tenant_id=tenantId,
            user_id=userId,
            role_key=body.roleKey,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _operating_result_response(
        tenant_id=tenantId,
        user_id=userId,
        result=result,
    )


@router.delete(
    "/tenants/{tenantId}/users/{userId}/operating-role",
    response_model=OperatingRoleMutationResponse,
)
def remove_operating_role(
    tenantId: str,
    userId: str,
    request: Request,
    actor: HumanActorContext = Depends(clerk_human_actor),
    session: Session = Depends(platform_session),
) -> OperatingRoleMutationResponse:
    _require_tenant_role_admin(actor, tenantId)
    try:
        result = OperatingRoleAssignmentService(session).remove_role(
            tenant_id=tenantId,
            user_id=userId,
            actor_user_id=actor.user_id,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return _operating_result_response(
        tenant_id=tenantId,
        user_id=userId,
        result=result,
    )
