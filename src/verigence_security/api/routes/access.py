from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from verigence_security.adapters.identity import AuthenticatedIdentity
from verigence_security.adapters.network_risk import NetworkRiskAdapter
from verigence_security.api.dependencies import (
    bearer_token,
    identity_from_token,
    network_adapter,
    repository,
    source_ip,
    token_service,
)
from verigence_security.api.schemas import (
    AccessSessionRequest,
    AccessTokenResponse,
    HumanLoginRequest,
    HumanLoginResponse,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import SecurityError, security_error
from verigence_security.core.observability import attach_trusted_user_id
from verigence_security.core.types import ActorType
from verigence_security.repositories.human_observation_repository import HumanObservationRepository
from verigence_security.repositories.security_repository import SecurityRepository, UserContext
from verigence_security.services.access_service import MachineAccessService, UserAccessService
from verigence_security.services.clerk_credentials import ClerkCredentialService
from verigence_security.services.geo import GeoSample
from verigence_security.services.permissions import effective_user_permissions
from verigence_security.services.token_service import HumanTokenClaims, TokenService
from verigence_security.services.v2_human_actor import HumanActorAuthenticationService

router = APIRouter(prefix="/security/v1", tags=["Runtime Access"])
oauth_router = APIRouter(tags=["OAuth"])

TOKEN_EXCHANGE_GRANT = ":".join(("urn", "ietf", "params", "oauth", "grant-type", "token-exchange"))
ACCESS_TOKEN_TYPE = ":".join(("urn", "ietf", "params", "oauth", "token-type", "access_token"))


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


def _geo(body: AccessSessionRequest) -> GeoSample:
    return GeoSample(
        latitude=body.geo.latitude,
        longitude=body.geo.longitude,
        accuracy_meters=body.geo.accuracyMeters,
        captured_at=body.geo.capturedAt,
        source=body.geo.source,
        integrity_status=body.geo.integrityStatus,
        integrity_reason=body.geo.integrityReason,
    )


def _uuid_or_new(claims: dict[str, object], name: str) -> UUID:
    value = claims.get(name)
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            raise security_error("AUTH_TOKEN_INVALID") from None
    # Compatibility for a Security JWT issued immediately before this feature is deployed.
    return uuid4()


@router.post("/auth/login", response_model=HumanLoginResponse)
def credential_login(
    body: HumanLoginRequest,
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """Authenticate a global human USER through Security -> Clerk Backend API."""

    authenticated = ClerkCredentialService(settings, session=repo.s).authenticate(
        identifier=body.identifier,
        password=body.password.get_secret_value(),
    )
    identity = AuthenticatedIdentity(
        provider="CLERK",
        provider_subject=authenticated.clerk_user.user_id,
        session_id=f"clerk-backend-{uuid4()}",
    )
    actor = HumanActorAuthenticationService(repo.s).authenticate(identity)
    attach_trusted_user_id(actor.user_id)

    ttl = settings.platform_admin_token_ttl_minutes
    if ttl is None:
        raise RuntimeError("Configured Security human access-token lifetime is unavailable")
    expires_at = datetime.now(UTC) + timedelta(minutes=ttl)
    # Device context is already available locally to current Web/Mobile. Older clients remain
    # compatible by receiving an ephemeral observation device id until they upgrade.
    device_id = body.device.deviceId if body.device is not None else uuid4()
    session_id = uuid4()
    token = tokens.issue_human_token(
        HumanTokenClaims(
            user_id=actor.user_id,
            expires_at=expires_at,
            session_id=str(session_id),
            device_id=str(device_id),
        )
    )
    return {
        "accessToken": token,
        "expiresAtUtc": expires_at,
        "actorType": ActorType.USER.value,
        "isSuperAdmin": actor.is_super_admin,
        "sessionId": session_id,
        "deviceId": device_id,
    }


@router.post("/auth/refresh", response_model=HumanLoginResponse)
def refresh_human_access_token(
    authorization_token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """Renew a still-valid global human token after re-checking current USER/admin state."""

    claims = tokens.verify_human_token(authorization_token)
    actor = HumanActorAuthenticationService(repo.s).authenticate_user_id(str(claims["sub"]))
    attach_trusted_user_id(actor.user_id)

    session_id = _uuid_or_new(claims, "session_id")
    device_id = _uuid_or_new(claims, "device_id")
    observation = HumanObservationRepository(repo.s)
    status = observation.session_status(
        user_id=actor.user_id,
        session_id=session_id,
        device_id=device_id,
    )
    # Observation persistence is deliberately fail-open while it is being introduced. Only an
    # explicit terminal/superseded record denies renewal; a missing async observation record does
    # not create a new availability dependency.
    if status == "SUPERSEDED":
        raise security_error("SESSION_SUPERSEDED")
    if status in {"ENDED", "REVOKED"}:
        raise security_error("SESSION_REVOKED")

    ttl = settings.platform_admin_token_ttl_minutes
    if ttl is None:
        raise RuntimeError("Configured Security human access-token lifetime is unavailable")
    expires_at = datetime.now(UTC) + timedelta(minutes=ttl)
    token = tokens.issue_human_token(
        HumanTokenClaims(
            user_id=actor.user_id,
            expires_at=expires_at,
            session_id=str(session_id),
            device_id=str(device_id),
        )
    )
    if status == "ACTIVE":
        observation.touch_active_session(
            user_id=actor.user_id,
            session_id=session_id,
            device_id=device_id,
            token_expires_at=expires_at,
            now=datetime.now(UTC),
        )
    return {
        "accessToken": token,
        "expiresAtUtc": expires_at,
        "actorType": ActorType.USER.value,
        "isSuperAdmin": actor.is_super_admin,
        "sessionId": session_id,
        "deviceId": device_id,
    }


@router.post("/access-sessions", response_model=AccessTokenResponse, deprecated=True)
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
    """Legacy identity-token bridge retained for migration/test compatibility; not channel-facing."""

    _ = idempotency_key
    identity = identity_from_token(authorization_token, settings)
    runtime_repo = GroupAwareSecurityRepository(repo.s)
    return UserAccessService(runtime_repo, network, tokens).create_or_reuse(
        identity=identity,
        tenant_id=str(body.tenantId),
        device_id=str(body.deviceId),
        geo=_geo(body),
        source_ip=ip,
        correlation_id=request.state.correlation_id,
    )


def _parse_form(body: bytes) -> dict[str, str]:
    values = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: items[-1] for key, items in values.items() if items}


def _basic_client(request: Request) -> tuple[str, str] | None:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
    except (UnicodeDecodeError, ValueError):
        return None
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


def _oauth_error(
    error: str,
    description: str | None = None,
    *,
    status_code: int = 400,
    basic_challenge: bool = False,
) -> JSONResponse:
    content: dict[str, str] = {"error": error}
    if description:
        content["error_description"] = description
    headers = {"WWW-Authenticate": "Basic"} if basic_challenge else None
    return JSONResponse(status_code=status_code, content=content, headers=headers)


def _oauth_success(result: dict[str, object]) -> JSONResponse:
    access_token = result.get("accessToken")
    expires_at = result.get("expiresAtUtc")
    permissions = result.get("permissions")
    if (
        not isinstance(access_token, str)
        or not isinstance(expires_at, datetime)
        or not isinstance(permissions, list)
        or not all(isinstance(permission, str) for permission in permissions)
    ):
        raise RuntimeError("Machine access service returned an invalid OAuth result")
    expires_in = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
    return JSONResponse(
        content={
            "access_token": access_token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": expires_in,
            "scope": " ".join(permissions),
        }
    )


def _oauth_security_error(exc: SecurityError) -> JSONResponse:
    if exc.code in {
        "MACHINE_CREDENTIAL_INVALID",
        "MACHINE_CREDENTIAL_EXPIRED",
        "PRINCIPAL_NOT_ACTIVE",
        "ACTOR_TYPE_NOT_ALLOWED",
    }:
        return _oauth_error("invalid_client", status_code=401, basic_challenge=True)
    if exc.code in {
        "TENANT_NOT_ACTIVE",
        "TENANT_OFFBOARDING",
        "TENANT_SECURITY_NOT_READY",
        "PRINCIPAL_TENANT_SCOPE_REQUIRED",
        "AUTH_TOKEN_INVALID",
        "AUTH_TOKEN_EXPIRED",
    }:
        return _oauth_error("invalid_grant", "authorization grant is invalid")
    if exc.code == "PERMISSION_DENIED":
        return _oauth_error("invalid_scope", "requested permission is not authorized")
    raise exc


@oauth_router.post("/oauth/token")
async def oauth_token(
    request: Request,
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
    ip: str = Depends(source_ip),
) -> JSONResponse:
    try:
        form = _parse_form(await request.body())
    except UnicodeDecodeError:
        return _oauth_error("invalid_request", "request body is not valid form data")

    client = _basic_client(request)
    if client is None:
        return _oauth_error("invalid_client", status_code=401, basic_challenge=True)
    client_id, client_secret = client
    grant_type = form.get("grant_type", "")
    requested_permissions = form.get("scope", "").split()
    service = MachineAccessService(repo, tokens)

    try:
        if grant_type == "client_credentials":
            tenant_id = form.get("tenant_id", "")
            if not tenant_id:
                return _oauth_error("invalid_request", "tenant_id is required")
            result = service.issue_machine_token(
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
                requested_permissions=requested_permissions,
                source_ip=ip,
                correlation_id=request.state.correlation_id,
            )
        elif grant_type == TOKEN_EXCHANGE_GRANT:
            if form.get("subject_token_type", ACCESS_TOKEN_TYPE) != ACCESS_TOKEN_TYPE:
                return _oauth_error("invalid_request", "unsupported subject_token_type")
            subject_token = form.get("subject_token", "")
            if not subject_token:
                return _oauth_error("invalid_request", "subject_token is required")
            result = service.exchange_user_token(
                client_id=client_id,
                client_secret=client_secret,
                subject_token=subject_token,
                requested_permissions=requested_permissions,
            )
        else:
            return _oauth_error("unsupported_grant_type", "unsupported grant_type")
    except SecurityError as exc:
        return _oauth_security_error(exc)
    except ValueError:
        return _oauth_error("invalid_scope", "requested permission is not authorized")

    return _oauth_success(result)
