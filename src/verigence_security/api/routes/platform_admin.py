from __future__ import annotations

from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.platform_schemas import (
    PlatformTenantCreateRequest,
    PlatformTenantHardDeleteResponse,
    PlatformTenantResponse,
    PlatformTenantUpdateRequest,
)
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.platform_admin import (
    PlatformTenantService,
    TenantCreateIdempotencyConflict,
)
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1/platform", tags=["Platform Administration"])


def _require_super_admin(actor: HumanActorContext) -> None:
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")


def _has_module_admin(actor: HumanActorContext) -> bool:
    return any(scope.role_key == "ModuleAdmin" for scope in actor.admin_scopes)


def _tenant_admin_scope_ids(actor: HumanActorContext) -> set[str]:
    return {
        str(scope.scope_id)
        for scope in actor.admin_scopes
        if scope.role_key == "TenantAdmin"
        and scope.scope_type == "TENANT"
        and scope.scope_id is not None
    }


def _require_tenant_metadata_access(actor: HumanActorContext, tenant_id: str) -> None:
    if actor.is_super_admin or _has_module_admin(actor) or actor.is_tenant_admin(tenant_id):
        return
    raise security_error("PERMISSION_DENIED")


def _require_tenant_update_access(actor: HumanActorContext, tenant_id: str) -> None:
    if actor.is_super_admin or actor.is_tenant_admin(tenant_id):
        return
    raise security_error("PERMISSION_DENIED")


def _generated_tenant_code() -> str:
    # UC02 keeps Tenant Code as an opaque Security-owned identifier. The existing
    # tenant_code column accepts short hyphenated strings; UUID hex keeps the value
    # unique, internal, and within the existing 80-character storage contract.
    return f"tenant-{uuid4().hex}"


@router.post(
    "/tenants",
    response_model=PlatformTenantResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_tenant(
    body: PlatformTenantCreateRequest,
    request: Request,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key", min_length=1)],
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    try:
        tenant = PlatformTenantService(session).create_tenant(
            actor_user_id=actor.user_id,
            tenant_code=_generated_tenant_code(),
            tenant_name=body.tenantName,
            correlation_id=request.state.correlation_id,
            idempotency_key=idempotency_key,
        )
    except TenantCreateIdempotencyConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Generated Tenant code already exists") from exc
    return _tenant_response(tenant)


@router.get("/tenants", response_model=list[PlatformTenantResponse])
def list_tenants(
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> list[dict[str, object]]:
    rows = PlatformTenantService(session).list_tenants()
    if actor.is_super_admin or _has_module_admin(actor):
        return [_tenant_response(row) for row in rows]
    allowed_tenants = _tenant_admin_scope_ids(actor)
    if not allowed_tenants:
        raise security_error("PERMISSION_DENIED")
    return [
        _tenant_response(row)
        for row in rows
        if str(row["tenant_id"]) in allowed_tenants
    ]


@router.get("/tenants/{tenantId}", response_model=PlatformTenantResponse)
def get_tenant(
    tenantId: str,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_tenant_metadata_access(actor, tenantId)
    tenant = PlatformTenantService(session).get_tenant(tenantId)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _tenant_response(tenant)


@router.patch("/tenants/{tenantId}", response_model=PlatformTenantResponse)
def update_tenant(
    tenantId: str,
    body: PlatformTenantUpdateRequest,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_tenant_update_access(actor, tenantId)
    tenant = PlatformTenantService(session).update_tenant_name(
        actor_user_id=actor.user_id,
        tenant_id=tenantId,
        tenant_name=body.tenantName,
        correlation_id=request.state.correlation_id,
    )
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _tenant_response(tenant)


@router.post("/tenants/{tenantId}/activate", response_model=PlatformTenantResponse)
def activate_tenant(
    tenantId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    try:
        tenant = PlatformTenantService(session).activate_tenant(
            actor_user_id=actor.user_id,
            tenant_id=tenantId,
            correlation_id=request.state.correlation_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _tenant_response(tenant)


@router.delete(
    "/tenants/{tenantId}",
    response_model=PlatformTenantHardDeleteResponse,
)
def hard_delete_tenant(
    tenantId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _require_super_admin(actor)
    result = PlatformTenantService(session).hard_delete_tenant(
        actor_user_id=actor.user_id,
        tenant_id=tenantId,
        correlation_id=request.state.correlation_id,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {
        "tenantId": result.tenant_id,
        "status": "DELETED",
        "deletedAtUtc": result.deleted_at_utc,
        "alreadyDeleted": result.already_deleted,
    }


def _tenant_response(row: dict[str, object]) -> dict[str, object]:
    return {
        "tenantId": str(row["tenant_id"]),
        "tenantCode": row["tenant_code"],
        "tenantName": row["tenant_name"],
        "status": row["status"],
        "createdAtUtc": row["created_at_utc"],
        "updatedAtUtc": row["updated_at_utc"],
    }
