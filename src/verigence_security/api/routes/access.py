from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Header, Request

from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.api.dependencies import (
    bearer_token,
    identity_from_token,
    network_adapter,
    repository,
    source_ip,
    token_service,
)
from verigence_security.api.schemas import AccessSessionRequest, AccessTokenResponse
from verigence_security.config import Settings, get_settings
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.access_service import UserAccessService
from verigence_security.services.geo import GeoSample
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1", tags=["Runtime Access"])


class GroupAwareSecurityRepository(SecurityRepository):
    def effective_user_permissions(
        self,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> tuple[list[str], list[str]]:
        return effective_user_permissions(self.s, tenant_id, user_id, now)


@router.post("/access-sessions", response_model=AccessTokenResponse)
def create_access_session(
    body: AccessSessionRequest,
    request: Request,
    authorization_token: str = Depends(bearer_token),
    idempotency_key: str = Header(..., alias="Idempotency-Key", max_length=200),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    network: NetworkRiskAdapter = Depends(network_adapter),
    tokens: TokenService = Depends(token_service),
    ip: str = Depends(source_ip),
) -> dict[str, object]:
    # Persistent same-key replay across stateless replicas still requires the approved
    # idempotency store tracked in IMPLEMENTATION_STATUS.
    _ = idempotency_key

    identity = identity_from_token(authorization_token, settings)
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
