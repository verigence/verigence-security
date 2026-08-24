from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends

from verigence_security.api.dependencies import bearer_token, repository, token_service
from verigence_security.api.schemas import HumanLoginResponse
from verigence_security.config import Settings, get_settings
from verigence_security.core.observability import attach_trusted_user_id
from verigence_security.core.types import ActorType
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.token_service import HumanTokenClaims, TokenService
from verigence_security.services.v2_human_actor import HumanActorAuthenticationService

router = APIRouter(prefix="/security/v1/auth", tags=["Runtime Access"])


@router.post("/refresh", response_model=HumanLoginResponse)
def refresh_human_access_token(
    authorization_token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """Renew a still-valid human token after re-checking current USER/admin state.

    The caller must present a valid, unexpired Security human token. No password or
    external identity-provider call is repeated. Current USER/principal/admin state is
    resolved from Security-owned data before a replacement token is issued.
    """

    claims = tokens.verify_human_token(authorization_token)
    actor = HumanActorAuthenticationService(repo.s).authenticate_user_id(str(claims["sub"]))
    attach_trusted_user_id(actor.user_id)

    ttl = settings.platform_admin_token_ttl_minutes
    if ttl is None:
        raise RuntimeError("Configured Security human access-token lifetime is unavailable")
    expires_at = datetime.now(UTC) + timedelta(minutes=ttl)
    token = tokens.issue_human_token(
        HumanTokenClaims(
            user_id=actor.user_id,
            expires_at=expires_at,
        )
    )
    return {
        "accessToken": token,
        "expiresAtUtc": expires_at,
        "actorType": ActorType.USER.value,
        "isSuperAdmin": actor.is_super_admin,
    }
