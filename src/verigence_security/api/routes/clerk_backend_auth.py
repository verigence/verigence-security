from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.api.clerk_schemas import (
    ClerkCredentialRequest,
    ClerkUserAccessLoginRequest,
)
from verigence_security.api.dependencies import network_adapter, repository, source_ip, token_service
from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.platform_schemas import PlatformTokenResponse
from verigence_security.api.schemas import AccessTokenResponse
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.access_service import UserAccessService
from verigence_security.services.clerk_auth import (
    ClerkCredentialService,
    ClerkPlatformAuthenticationService,
)
from verigence_security.services.geo import GeoSample
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1", tags=["Authentication"])


class GroupAwareSecurityRepository(SecurityRepository):
    def effective_user_permissions(
        self,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> tuple[list[str], list[str]]:
        return effective_user_permissions(self.s, tenant_id, user_id, now)


@router.post("/platform/bootstrap/claim", response_model=PlatformTokenResponse)
def claim_platform_super_admin(
    body: ClerkCredentialRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    result = ClerkPlatformAuthenticationService(session, settings).bootstrap_claim(
        identifier=body.identifier,
        password=body.password,
        totp_code=body.totpCode,
        correlation_id=request.state.correlation_id,
    )
    return {
        "accessToken": result.access_token,
        "expiresAtUtc": result.expires_at_utc,
        "userId": result.user_id,
        "roles": list(result.roles),
        "permissions": list(result.permissions),
        "mustChangePassword": False,
    }


@router.post("/platform/auth/session", response_model=PlatformTokenResponse)
def create_platform_session(
    body: ClerkCredentialRequest,
    settings: Settings = Depends(get_settings),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    result = ClerkPlatformAuthenticationService(session, settings).login(
        identifier=body.identifier,
        password=body.password,
        totp_code=body.totpCode,
    )
    return {
        "accessToken": result.access_token,
        "expiresAtUtc": result.expires_at_utc,
        "userId": result.user_id,
        "roles": list(result.roles),
        "permissions": list(result.permissions),
        "mustChangePassword": False,
    }


@router.post("/auth/login", response_model=AccessTokenResponse)
def create_user_access_from_clerk(
    body: ClerkUserAccessLoginRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    network: NetworkRiskAdapter = Depends(network_adapter),
    tokens: TokenService = Depends(token_service),
    ip: str = Depends(source_ip),
) -> dict[str, object]:
    authenticated = ClerkCredentialService(settings).authenticate(
        identifier=body.identifier,
        password=body.password,
        totp_code=body.totpCode,
    )
    clerk_user = authenticated.clerk_user
    identity = AuthenticatedIdentity(
        provider="CLERK",
        provider_subject=clerk_user.user_id,
        session_id=f"clerk-backend-{uuid4()}",
    )
    geo = GeoSample(
        latitude=body.geo.latitude,
        longitude=body.geo.longitude,
        accuracy_meters=body.geo.accuracyMeters,
        captured_at=body.geo.capturedAt,
        source=body.geo.source,
        integrity_status=body.geo.integrityStatus,
        integrity_reason=body.geo.integrityReason,
    )
    runtime_repo = GroupAwareSecurityRepository(repo.s)
    return UserAccessService(runtime_repo, network, tokens).create_or_reuse(
        identity=identity,
        tenant_id=str(body.tenantId),
        device_id=str(body.deviceId),
        geo=geo,
        source_ip=ip,
        correlation_id=request.state.correlation_id,
    )
