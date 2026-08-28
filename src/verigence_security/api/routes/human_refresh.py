from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends

from verigence_security.api.dependencies import bearer_token, repository, token_service
from verigence_security.api.schemas import HumanLoginResponse
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.core.observability import attach_trusted_user_id
from verigence_security.core.types import ActorType
from verigence_security.repositories.human_observation_repository import HumanObservationRepository
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.token_service import HumanTokenClaims, TokenService
from verigence_security.services.v2_human_actor import HumanActorAuthenticationService

router = APIRouter(prefix="/security/v1/auth", tags=["Runtime Access"])


def _uuid_or_new(claims: dict[str, object], name: str) -> UUID:
    value = claims.get(name)
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError:
            raise security_error("AUTH_TOKEN_INVALID") from None
    return uuid4()


@router.post("/refresh", response_model=HumanLoginResponse)
def refresh_human_access_token(
    authorization_token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """Renew a still-valid human token after re-checking current USER/admin/session state.

    The caller presents a valid, unexpired Security human token. No password or external identity-
    provider call is repeated. Observation persistence remains fail-open unless an existing session
    is explicitly SUPERSEDED/ENDED/REVOKED.
    """

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
