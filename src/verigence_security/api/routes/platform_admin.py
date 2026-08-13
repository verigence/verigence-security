from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import (
    platform_claims,
    platform_session,
    require_platform_permission,
)
from verigence_security.api.platform_schemas import (
    PlatformLoginRequest,
    PlatformMeResponse,
    PlatformPasswordChangeRequest,
    PlatformTenantCreateRequest,
    PlatformTenantResponse,
    PlatformTenantUpdateRequest,
    PlatformTokenResponse,
)
from verigence_security.config import Settings, get_settings
from verigence_security.services.platform_admin import (
    PlatformAuthenticationService,
    PlatformTenantService,
)

router = APIRouter(prefix="/security/v1/platform", tags=["Platform Administration"])


@router.post("/auth/login", response_model=PlatformTokenResponse)
def platform_login(
    body: PlatformLoginRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    result = PlatformAuthenticationService(session, settings).login(
        login_name=body.loginName,
        password=body.password,
    )
    return {
        "accessToken": result.access_token,
        "expiresAtUtc": result.expires_at_utc,
        "userId": result.user_id,
        "roles": list(result.roles),
        "permissions": list(result.permissions),
        "mustChangePassword": result.must_change_password,
    }


@router.post("/auth/change-password", status_code=status.HTTP_204_NO_CONTENT)
def platform_change_password(
    body: PlatformPasswordChangeRequest,
    request: Request,
    claims: dict[str, Any] = Depends(platform_claims),
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> Response:
    PlatformAuthenticationService(session, settings).change_password(
        user_id=str(claims["sub"]),
        new_password=body.newPassword,
        correlation_id=request.state.correlation_id,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=PlatformMeResponse)
def platform_me(
    claims: dict[str, Any] = Depends(platform_claims),
) -> dict[str, object]:
    return {
        "userId": str(claims["sub"]),
        "roles": [str(value) for value in claims.get("roles", [])],
        "permissions": [str(value) for value in claims.get("permissions", [])],
        "mustChangePassword": bool(claims.get("must_change_password")),
    }


@router.post(
    "/tenants",
    response_model=PlatformTenantResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_tenant(
    body: PlatformTenantCreateRequest,
    request: Request,
    claims: dict[str, Any] = Depends(require_platform_permission("security.tenant.create")),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    self_onboarding = body.selfOnboarding
    try:
        tenant = PlatformTenantService(session).create_tenant(
            actor_user_id=str(claims["sub"]),
            tenant_code=body.tenantCode,
            tenant_name=body.tenantName,
            correlation_id=request.state.correlation_id,
            self_onboarding_enabled=(self_onboarding.enabled if self_onboarding else False),
            self_onboarding_token=(self_onboarding.token if self_onboarding else None),
        )
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail="Tenant code already exists") from exc
    return _tenant_response(tenant)


@router.get("/tenants", response_model=list[PlatformTenantResponse])
def list_tenants(
    claims: dict[str, Any] = Depends(require_platform_permission("security.tenant.read")),
    session: Session = Depends(platform_session),
) -> list[dict[str, object]]:
    _ = claims
    return [_tenant_response(row) for row in PlatformTenantService(session).list_tenants()]


@router.get("/tenants/{tenantId}", response_model=PlatformTenantResponse)
def get_tenant(
    tenantId: str,
    claims: dict[str, Any] = Depends(require_platform_permission("security.tenant.read")),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    _ = claims
    tenant = PlatformTenantService(session).get_tenant(tenantId)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _tenant_response(tenant)


@router.patch("/tenants/{tenantId}", response_model=PlatformTenantResponse)
def update_tenant(
    tenantId: str,
    body: PlatformTenantUpdateRequest,
    request: Request,
    claims: dict[str, Any] = Depends(require_platform_permission("security.tenant.update")),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    tenant = PlatformTenantService(session).update_tenant_name(
        actor_user_id=str(claims["sub"]),
        tenant_id=tenantId,
        tenant_name=body.tenantName,
        correlation_id=request.state.correlation_id,
    )
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _tenant_response(tenant)


def _tenant_response(row: dict[str, object]) -> dict[str, object]:
    return {
        "tenantId": str(row["tenant_id"]),
        "tenantCode": row["tenant_code"],
        "tenantName": row["tenant_name"],
        "status": row["status"],
        "createdAtUtc": row["created_at_utc"],
        "updatedAtUtc": row["updated_at_utc"],
    }
