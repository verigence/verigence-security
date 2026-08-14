from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import text

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
from verigence_security.core.errors import security_error
from verigence_security.repositories.security_repository import SecurityRepository, UserContext
from verigence_security.services.access_service import UserAccessService
from verigence_security.services.geo import GeoSample
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1", tags=["Runtime Access"])


class GroupAwareSecurityRepository(SecurityRepository):
    """v1.4.2 USER runtime: global USER + Tenant-scoped authorization, no membership gate."""

    def effective_user_permissions(
        self,
        tenant_id: str,
        user_id: str,
        now: datetime,
    ) -> tuple[list[str], list[str]]:
        return effective_user_permissions(self.s, tenant_id, user_id, now)

    def get_user_context(self, user_id: str, tenant_id: str, now: datetime) -> UserContext:
        _ = now
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,u.status AS user_status,p.status AS principal_status,
                       COALESCE(a.authorization_version,1) AS authorization_version
                FROM security.users u
                JOIN security.security_principals p ON p.principal_id=u.user_id
                LEFT JOIN security.user_tenant_authorization_state a
                  ON a.user_id=u.user_id AND a.tenant_id=:tenant_id
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id, "tenant_id": tenant_id},
        ).mappings().first()
        if row is None:
            raise security_error("USER_NOT_ONBOARDED")
        if row["principal_status"] != "ACTIVE":
            raise security_error("PRINCIPAL_NOT_ACTIVE")
        if row["user_status"] != "ACTIVE":
            raise security_error("USER_NOT_ACTIVE")
        # UserContext retains legacy membership fields until the v1.3 model is physically retired.
        # They are deliberately inert in v1.4.2; authorization_version comes from the new state row.
        return UserContext(
            user_id=str(row["user_id"]),
            user_status=str(row["user_status"]),
            membership_id="",
            membership_status="NOT_REQUIRED",
            authorization_version=int(row["authorization_version"]),
        )

    def create_user_session(
        self,
        *,
        tenant_id: str,
        user_id: str,
        membership_id: str,
        device_id: str,
        location_id: str,
        authentication_source: str,
        authz_version: int,
        source_ip: str,
        vpn_status: str,
        expires_at: datetime,
        now: datetime,
    ) -> str:
        _ = membership_id
        session_id = str(uuid4())
        self.s.execute(
            text(
                """
                INSERT INTO security.access_sessions
                (access_session_id,tenant_id,principal_id,actor_type,membership_id,device_id,
                 location_id,authentication_source,authorization_version,source_ip,vpn_status,
                 started_at_utc,expires_at_utc,last_activity_at_utc,
                 last_geo_validated_at_utc,status)
                VALUES
                (:session_id,:tenant_id,:user_id,'USER',NULL,:device_id,
                 :location_id,:authentication_source,:authz_version,:source_ip,:vpn_status,
                 :now,:expires_at,:now,:now,'ACTIVE')
                """
            ),
            {
                "session_id": session_id,
                "tenant_id": tenant_id,
                "user_id": user_id,
                "device_id": device_id,
                "location_id": location_id,
                "authentication_source": authentication_source,
                "authz_version": authz_version,
                "source_ip": source_ip,
                "vpn_status": vpn_status,
                "now": now,
                "expires_at": expires_at,
            },
        )
        return session_id


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
