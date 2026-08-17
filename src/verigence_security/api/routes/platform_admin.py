from __future__ import annotations

from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.api.platform_dependencies import (
    platform_claims,
    platform_session,
    require_platform_permission,
)
from verigence_security.api.platform_schemas import (
    PlatformLoginRequest,
    PlatformMeResponse,
    PlatformTenantCreateRequest,
    PlatformTenantResponse,
    PlatformTenantUpdateRequest,
    PlatformTokenResponse,
)
from verigence_security.config import Settings, get_settings
from verigence_security.services.clerk_credentials import ClerkCredentialService
from verigence_security.services.platform_admin import PlatformTenantService
from verigence_security.services.platform_identity import PlatformIdentityResult, PlatformIdentityService

router = APIRouter(prefix="/security/v1/platform", tags=["Platform Administration"])


def _credential_identity(body: PlatformLoginRequest, settings: Settings) -> AuthenticatedIdentity:
    authenticated = ClerkCredentialService(settings).authenticate(
        identifier=body.loginName,
        password=body.password.get_secret_value(),
        totp_code=body.totpCode.get_secret_value() if body.totpCode is not None else None,
    )
    return AuthenticatedIdentity(
        provider="CLERK",
        provider_subject=authenticated.clerk_user.user_id,
        session_id=f"clerk-backend-{uuid4()}",
    )


def _token_response(result: PlatformIdentityResult) -> dict[str, object]:
    return {
        "accessToken": result.access_token,
        "expiresAtUtc": result.expires_at_utc,
        "userId": result.user_id,
        "roles": list(result.roles),
        "permissions": list(result.permissions),
        "mustChangePassword": False,
    }


@router.post("/bootstrap/claim", response_model=PlatformTokenResponse)
def claim_platform_super_admin(
    body: PlatformLoginRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    """Backend-only first Super Admin claim; Clerk credentials never leave Security."""

    identity = _credential_identity(body, settings)
    result = PlatformIdentityService(session, settings).bootstrap_claim(
        identity=identity,
        correlation_id=request.state.correlation_id,
    )
    return _token_response(result)


@router.post("/auth/login", response_model=PlatformTokenResponse)
def platform_login(
    body: PlatformLoginRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    """Verify credentials through Clerk Backend API and issue Security Platform Admin JWT."""

    identity = _credential_identity(body, settings)
    result = PlatformIdentityService(session, settings).login(identity=identity)
    return _token_response(result)


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
    try:
        tenant = PlatformTenantService(session).create_tenant(
            actor_user_id=str(claims["sub"]),
            tenant_code=body.tenantCode,
            tenant_name=body.tenantName,
            correlation_id=request.state.correlation_id,
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
