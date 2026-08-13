from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from verigence_security.api.schemas import (
    PlatformAdminBootstrapRequest,
    PlatformAdminBootstrapResponse,
    PlatformAdminLoginRequest,
    PlatformAdminTokenResponse,
    TenantAdminResponse,
    TenantCreateRequest,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.db.session import build_session_factory
from verigence_security.repositories.platform_admin_repository import PlatformAdminRepository
from verigence_security.services.platform_admin import (
    PlatformAdminService,
    PlatformAdminTokenService,
)

router = APIRouter(prefix="/security/v1/admin", tags=["platform-admin"])

platform_admin_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="PlatformAdminToken",
    bearerFormat="JWT",
    description="Short-lived Verigence platform Super Admin token.",
)


def platform_admin_service(
    settings: Settings = Depends(get_settings),
) -> Generator[PlatformAdminService, None, None]:
    factory = build_session_factory(settings)
    if factory is None:
        raise security_error("DATABASE_UNAVAILABLE")
    session = factory()
    try:
        yield PlatformAdminService(PlatformAdminRepository(session), settings)
    finally:
        session.close()


def require_platform_admin(
    credentials: HTTPAuthorizationCredentials | None = Security(platform_admin_bearer),
    settings: Settings = Depends(get_settings),
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise security_error("AUTH_TOKEN_INVALID")
    token = credentials.credentials.strip()
    if not token:
        raise security_error("AUTH_TOKEN_INVALID")
    return PlatformAdminTokenService(settings).verify(token)


@router.post(
    "/bootstrap",
    response_model=PlatformAdminBootstrapResponse,
    status_code=status.HTTP_201_CREATED,
)
def bootstrap_platform_admin(
    request: PlatformAdminBootstrapRequest,
    service: PlatformAdminService = Depends(platform_admin_service),
) -> PlatformAdminBootstrapResponse:
    try:
        result = service.bootstrap(
            username=request.username,
            display_name=request.displayName,
            password=request.password,
            now=datetime.now(UTC),
        )
    except ValueError as exc:
        code = str(exc)
        if code == "PLATFORM_ADMIN_BOOTSTRAP_NOT_ALLOWED":
            raise HTTPException(status_code=403, detail=code) from exc
        if code == "PLATFORM_ADMIN_ALREADY_BOOTSTRAPPED":
            raise HTTPException(status_code=409, detail=code) from exc
        raise
    return PlatformAdminBootstrapResponse(
        adminId=result["admin_id"],
        username=result["username"],
        displayName=result["display_name"],
        mustChangePassword=result["must_change_password"],
    )


@router.post("/auth/login", response_model=PlatformAdminTokenResponse)
def platform_admin_login(
    request: PlatformAdminLoginRequest,
    service: PlatformAdminService = Depends(platform_admin_service),
) -> PlatformAdminTokenResponse:
    result = service.login(
        username=request.username,
        password=request.password,
        now=datetime.now(UTC),
    )
    return PlatformAdminTokenResponse(
        accessToken=result["access_token"],
        expiresAtUtc=result["expires_at"],
        adminId=result["admin_id"],
        username=result["username"],
        role=result["role"],
        mustChangePassword=result["must_change_password"],
    )


@router.post(
    "/tenants",
    response_model=TenantAdminResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_tenant(
    request: TenantCreateRequest,
    _: dict[str, Any] = Depends(require_platform_admin),
    service: PlatformAdminService = Depends(platform_admin_service),
) -> TenantAdminResponse:
    try:
        result = service.create_tenant(
            tenant_code=request.tenantCode,
            tenant_name=request.tenantName,
            now=datetime.now(UTC),
        )
    except ValueError as exc:
        if str(exc) == "TENANT_CODE_ALREADY_EXISTS":
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        raise
    return TenantAdminResponse(
        tenantId=result["tenant_id"],
        tenantCode=result["tenant_code"],
        tenantName=result["tenant_name"],
        status=result["status"],
    )


@router.get("/tenants", response_model=list[TenantAdminResponse])
def list_tenants(
    _: dict[str, Any] = Depends(require_platform_admin),
    service: PlatformAdminService = Depends(platform_admin_service),
) -> list[TenantAdminResponse]:
    return [
        TenantAdminResponse(
            tenantId=row["tenant_id"],
            tenantCode=row["tenant_code"],
            tenantName=row["tenant_name"],
            status=row["status"],
            createdAtUtc=row["created_at_utc"],
            updatedAtUtc=row["updated_at_utc"],
        )
        for row in service.list_tenants()
    ]
