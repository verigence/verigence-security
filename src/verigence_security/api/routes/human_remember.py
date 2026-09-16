from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Response

from verigence_security.api.dependencies import bearer_token, repository, token_service
from verigence_security.api.schemas import (
    HumanLogoutRequest,
    HumanRememberRequest,
    HumanRememberResponse,
    HumanResumeRequest,
    HumanResumeResponse,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import SecurityError, security_error
from verigence_security.core.observability import attach_trusted_user_id
from verigence_security.core.types import ActorType
from verigence_security.repositories.human_observation_repository import HumanObservationRepository
from verigence_security.repositories.human_remember_repository import HumanRememberRepository
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.token_service import HumanTokenClaims, TokenService
from verigence_security.services.v2_human_actor import HumanActorAuthenticationService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/security/v1/auth", tags=["Runtime Access"])

REMEMBER_COOKIE = "verigence_remember"


def _hash_credential(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_credential() -> str:
    # 32 random bytes => 256 bits of entropy before URL-safe encoding.
    return secrets.token_urlsafe(32)


def set_web_remember_cookie(
    response: Response,
    credential: str,
    expires_at: datetime,
    now: datetime,
) -> None:
    max_age = max(1, int((expires_at - now).total_seconds()))
    response.set_cookie(
        key=REMEMBER_COOKIE,
        value=credential,
        max_age=max_age,
        expires=expires_at,
        path="/security/v1/auth",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def clear_web_remember_cookie(response: Response) -> None:
    response.delete_cookie(
        key=REMEMBER_COOKIE,
        path="/security/v1/auth",
        secure=True,
        httponly=True,
        samesite="strict",
    )


def _issue_remember_credential(
    *,
    repo: SecurityRepository,
    user_id: str,
    session_id: str,
    device_id: str,
    settings: Settings,
    now: datetime,
) -> tuple[str, datetime]:
    credential = _new_credential()
    expires_at = now + timedelta(days=settings.human_remember_session_ttl_days)
    HumanRememberRepository(repo.s).replace_for_login(
        user_id=user_id,
        session_id=session_id,
        device_id=device_id,
        token_hash=_hash_credential(credential),
        expires_at=expires_at,
        now=now,
    )
    return credential, expires_at


def _supplied_credential(
    body: HumanResumeRequest | HumanLogoutRequest,
    cookie: str | None,
) -> str | None:
    device = body.device
    if device is not None and device.deviceType == "MOBILE":
        return body.rememberToken
    return cookie


def _valid_claim_uuid(claims: dict[str, object], name: str) -> UUID:
    value = claims.get(name)
    if not isinstance(value, str):
        raise security_error("AUTH_TOKEN_INVALID")
    try:
        return UUID(value)
    except ValueError:
        raise security_error("AUTH_TOKEN_INVALID") from None


def _assert_session_resumable(
    *,
    repo: SecurityRepository,
    user_id: str,
    session_id: UUID,
    device_id: UUID,
) -> None:
    status = HumanObservationRepository(repo.s).session_status(
        user_id=user_id,
        session_id=session_id,
        device_id=device_id,
    )
    # Observation registration is intentionally asynchronous and fail-open. A missing row therefore
    # does not create a new availability dependency, but any explicit terminal state blocks resume.
    if status == "SUPERSEDED":
        raise security_error("SESSION_SUPERSEDED")
    if status in {"ENDED", "REVOKED"}:
        raise security_error("SESSION_REVOKED")


@router.post("/remember", response_model=HumanRememberResponse)
def remember_human_session(
    body: HumanRememberRequest,
    response: Response,
    authorization_token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """Enable persistent sign-in without changing the normal short-lived access-token contract.

    This endpoint is deliberately separate from credential login so remember-session persistence can
    fail without making successful password authentication unavailable or slower.
    """

    claims = tokens.verify_human_token(authorization_token)
    user_id = str(claims["sub"])
    session_id = _valid_claim_uuid(claims, "session_id")
    token_device_id = _valid_claim_uuid(claims, "device_id")
    if body.device.deviceId != token_device_id:
        raise security_error("AUTH_TOKEN_INVALID")

    actor = HumanActorAuthenticationService(repo.s).authenticate_user_id(user_id)
    attach_trusted_user_id(actor.user_id)
    _assert_session_resumable(
        repo=repo,
        user_id=user_id,
        session_id=session_id,
        device_id=token_device_id,
    )

    now = datetime.now(UTC)
    credential, expires_at = _issue_remember_credential(
        repo=repo,
        user_id=user_id,
        session_id=str(session_id),
        device_id=str(token_device_id),
        settings=settings,
        now=now,
    )

    if body.device.deviceType == "WEB":
        set_web_remember_cookie(response, credential, expires_at, now)
        mobile_credential: str | None = None
    else:
        mobile_credential = credential

    return {
        "remembered": True,
        "rememberToken": mobile_credential,
        "rememberExpiresAtUtc": expires_at,
    }


@router.post("/resume", response_model=HumanResumeResponse)
def resume_human_session(
    body: HumanResumeRequest,
    response: Response,
    remember_cookie: str | None = Cookie(default=None, alias=REMEMBER_COOKIE),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """Exchange a rotating remembered-session credential for a normal short-lived access token."""

    try:
        return _resume_human_session(body, response, remember_cookie, settings, repo, tokens)
    except SecurityError:
        raise
    except Exception as exc:
        # Temporary diagnostic: a real, reproducible 500 on this route has no
        # server-log access from the reporting side. SecurityError's own
        # handler puts `detail` directly in the JSON response body (unlike
        # the generic 500 handler's fixed "Internal Server Error" text), so
        # this turns "check Railway logs" into "read the Network tab" for
        # whoever reproduces it next. Revert once the real cause is found.
        logger.exception("security_resume_unexpected_error")
        raise security_error(
            "RESUME_INTERNAL_ERROR",
            detail=f"{type(exc).__name__}: {exc}",
        ) from exc


def _resume_human_session(
    body: HumanResumeRequest,
    response: Response,
    remember_cookie: str | None,
    settings: Settings,
    repo: SecurityRepository,
    tokens: TokenService,
) -> dict[str, object]:
    credential = _supplied_credential(body, remember_cookie)
    if not credential:
        raise security_error("AUTH_TOKEN_INVALID")

    remember = HumanRememberRepository(repo.s)
    credential_hash = _hash_credential(credential)
    record = remember.lock_by_hash(token_hash=credential_hash)
    if record is None:
        raise security_error("AUTH_TOKEN_INVALID")

    session_id = UUID(str(record["access_session_id"]))
    user_id = str(record["user_id"])
    device_id = UUID(str(record["device_id"]))
    now = datetime.now(UTC)

    # A replay of the immediately previous rotated credential is strong evidence of copying. Revoke
    # the active family rather than allowing either holder to continue using the remembered session.
    if record.get("previous_token_hash") == credential_hash:
        remember.revoke_session(session_id=str(session_id), now=now)
        logger.warning(
            "security_remember_token_replay",
            extra={"event_name": "security_remember_token_replay", "outcome": "DENIED"},
        )
        raise security_error("AUTH_TOKEN_INVALID")

    if record.get("token_hash") != credential_hash or record.get("status") != "ACTIVE":
        raise security_error("AUTH_TOKEN_INVALID")
    if record["expires_at_utc"] <= now:
        remember.revoke_session(session_id=str(session_id), now=now)
        raise security_error("AUTH_TOKEN_EXPIRED")
    if body.device.deviceId != device_id:
        raise security_error("AUTH_TOKEN_INVALID")

    actor = HumanActorAuthenticationService(repo.s).authenticate_user_id(user_id)
    attach_trusted_user_id(actor.user_id)
    try:
        _assert_session_resumable(
            repo=repo,
            user_id=user_id,
            session_id=session_id,
            device_id=device_id,
        )
    except Exception:
        remember.revoke_session(session_id=str(session_id), now=now)
        raise

    ttl = settings.platform_admin_token_ttl_minutes
    if ttl is None:
        raise RuntimeError("Configured Security human access-token lifetime is unavailable")
    access_expires_at = now + timedelta(minutes=ttl)
    access_token = tokens.issue_human_token(
        HumanTokenClaims(
            user_id=user_id,
            expires_at=access_expires_at,
            session_id=str(session_id),
            device_id=str(device_id),
        )
    )

    rotated = _new_credential()
    remember.rotate(
        session_id=str(session_id),
        new_token_hash=_hash_credential(rotated),
        now=now,
    )

    if body.device.deviceType == "WEB":
        set_web_remember_cookie(response, rotated, record["expires_at_utc"], now)
        mobile_credential: str | None = None
    else:
        mobile_credential = rotated

    return {
        "accessToken": access_token,
        "expiresAtUtc": access_expires_at,
        "actorType": ActorType.USER.value,
        "isSuperAdmin": actor.is_super_admin,
        "sessionId": session_id,
        "deviceId": device_id,
        "rememberToken": mobile_credential,
        "rememberExpiresAtUtc": record["expires_at_utc"],
        "remembered": True,
    }


@router.post("/logout", status_code=204)
def logout_human_session(
    body: HumanLogoutRequest,
    response: Response,
    remember_cookie: str | None = Cookie(default=None, alias=REMEMBER_COOKIE),
    repo: SecurityRepository = Depends(repository),
) -> Response:
    """Revoke a remembered session if present; explicit logout remains fast and idempotent."""

    credential = _supplied_credential(body, remember_cookie)
    if credential:
        HumanRememberRepository(repo.s).revoke_by_hash(
            token_hash=_hash_credential(credential),
            now=datetime.now(UTC),
        )
    clear_web_remember_cookie(response)
    response.status_code = 204
    return response
