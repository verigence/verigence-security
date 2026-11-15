"""Signing in to another Verigence app from the Verigence app (product owner, 15 Nov 2026).

An employee signed in on the Verigence app on their phone opens SevaSutra and is signed in there without typing
their password again. It is the authorization-code flow with PKCE, with the Verigence app as the place the person
is already signed in:

1. SevaSutra (its server) makes a PKCE verifier and challenge and opens the Verigence app with the challenge.
2. The Verigence app asks the person, and calls ``POST /security/v1/auth/app-sign-in/code`` with their own
   access token: a one-time code for that app, valid two minutes.
3. The Verigence app hands the code back to SevaSutra, whose server calls
   ``POST /security/v1/auth/app-sign-in/token`` with its service token, the code and the verifier: it gets the
   person's own sign-in, exactly as if they had signed in with their password there.

Only apps registered here can be signed in to this way, each with the service integration that may exchange its
codes and the one address the code may be handed back to.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from verigence_security.api.dependencies import bearer_token, repository, source_ip, token_service
from verigence_security.api.schemas import HumanDeviceContext
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.core.observability import attach_trusted_user_id
from verigence_security.core.types import ActorType
from verigence_security.repositories.app_sign_in_repository import AppSignInRepository
from verigence_security.repositories.human_observation_repository import HumanObservationRepository
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.repositories.v2_authorization_repository import V2AuthorizationRepository
from verigence_security.services.access_blocks import require_not_blocked
from verigence_security.services.login_activity import record_login_attempt
from verigence_security.services.token_service import HumanTokenClaims, TokenService
from verigence_security.services.v2_human_actor import HumanActorAuthenticationService

router = APIRouter(prefix="/security/v1/auth/app-sign-in", tags=["Runtime Access"])

CODE_TTL = timedelta(minutes=2)


@dataclass(frozen=True, slots=True)
class AppClient:
    name: str
    # The service integration (its service token's subject) that may exchange this app's codes.
    integration: str
    # Where the Verigence app may hand a code back.
    redirect_uris: tuple[str, ...]


APPS: dict[str, AppClient] = {
    "sevasutra": AppClient(name="SevaSutra", integration="sevasutra", redirect_uris=("sevasutra://sso",)),
}


class AppSignInCodeRequest(BaseModel):
    client: str = Field(min_length=1, max_length=64)
    redirectUri: str = Field(min_length=1, max_length=300)
    codeChallenge: str = Field(min_length=43, max_length=128)
    codeChallengeMethod: Literal["S256"] = "S256"


class AppSignInCodeResponse(BaseModel):
    code: str
    expiresAtUtc: datetime
    client: str
    clientName: str


class AppSignInTokenRequest(BaseModel):
    code: str = Field(min_length=20, max_length=200)
    codeVerifier: str = Field(min_length=43, max_length=128)
    redirectUri: str = Field(min_length=1, max_length=300)
    device: HumanDeviceContext | None = None


class AppSignInTokenResponse(BaseModel):
    accessToken: str
    expiresAtUtc: datetime
    actorType: ActorType
    isSuperAdmin: bool = False
    sessionId: UUID
    deviceId: UUID
    email: str | None = None


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def pkce_challenge(verifier: str) -> str:
    """The S256 challenge of a PKCE verifier (RFC 7636): base64url of its SHA-256, without padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _claim_uuid(claims: dict[str, object], name: str) -> str | None:
    value = claims.get(name)
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


service_bearer = HTTPBearer(auto_error=False, scheme_name="ServiceIntegrationBearer", bearerFormat="JWT")


def _service_subject(
    credentials: HTTPAuthorizationCredentials | None = Security(service_bearer),
    tokens: TokenService = Depends(token_service),
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer" or not credentials.credentials.strip():
        raise security_error("AUTH_TOKEN_INVALID")
    claims = tokens.verify_service_token(credentials.credentials.strip(), audience="security")
    return str(claims["sub"])


@router.post("/code", response_model=AppSignInCodeResponse)
def app_sign_in_code(
    body: AppSignInCodeRequest,
    authorization_token: str = Depends(bearer_token),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
) -> dict[str, object]:
    """A one-time code that signs the caller in to another Verigence app (asked for by the Verigence app)."""

    app = APPS.get(body.client)
    if app is None or body.redirectUri not in app.redirect_uris:
        raise security_error("AUTH_TOKEN_INVALID", detail="This app cannot be signed in to from here")
    claims = tokens.verify_human_token(authorization_token)
    actor = HumanActorAuthenticationService(repo.s).authenticate_user_id(str(claims["sub"]))
    attach_trusted_user_id(actor.user_id)
    require_not_blocked(repo.s, user_id=actor.user_id, is_super_admin=actor.is_super_admin)
    session_id = _claim_uuid(claims, "session_id")
    device_id = _claim_uuid(claims, "device_id")
    # The Verigence app's own sign-in must still stand: a session ended or taken over elsewhere signs no one in.
    if session_id and device_id:
        status = HumanObservationRepository(repo.s).session_status(
            user_id=actor.user_id, session_id=UUID(session_id), device_id=UUID(device_id)
        )
        if status == "SUPERSEDED":
            raise security_error("SESSION_SUPERSEDED")
        if status in {"ENDED", "REVOKED"}:
            raise security_error("SESSION_REVOKED")
    now = datetime.now(UTC)
    code = secrets.token_urlsafe(32)
    expires_at = now + CODE_TTL
    AppSignInRepository(repo.s).create(
        code_hash=_hash(code),
        user_id=actor.user_id,
        client_key=body.client,
        redirect_uri=body.redirectUri,
        code_challenge=body.codeChallenge,
        from_session_id=session_id,
        from_device_id=device_id,
        now=now,
        expires_at=expires_at,
    )
    repo.commit()
    return {"code": code, "expiresAtUtc": expires_at, "client": body.client, "clientName": app.name}


@router.post("/token", response_model=AppSignInTokenResponse)
def app_sign_in_token(
    body: AppSignInTokenRequest,
    subject: str = Depends(_service_subject),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
    ip: str = Depends(source_ip),
) -> dict[str, object]:
    """The app's server exchanges the code (with its PKCE verifier) for the person's sign-in."""

    if not V2AuthorizationRepository(repo.s).active_service_integration(subject):
        raise security_error("AUTH_TOKEN_INVALID")
    now = datetime.now(UTC)
    store = AppSignInRepository(repo.s)
    taken = store.take(code_hash=_hash(body.code), now=now)
    repo.commit()
    app = APPS.get(str(taken["client_key"])) if taken else None
    if (
        taken is None
        or app is None
        or app.integration != subject
        or taken["redirect_uri"] != body.redirectUri
        or not secrets.compare_digest(pkce_challenge(body.codeVerifier), str(taken["code_challenge"]))
    ):
        raise security_error("AUTH_TOKEN_INVALID", detail="The sign-in code is not valid, was used, or has expired")
    user_id = str(taken["user_id"])
    actor = HumanActorAuthenticationService(repo.s).authenticate_user_id(user_id)
    attach_trusted_user_id(actor.user_id)
    device = body.device
    require_not_blocked(repo.s, user_id=actor.user_id, is_super_admin=actor.is_super_admin)
    record_login_attempt(
        settings,
        identifier=store.email_of(actor.user_id) or "",
        user_id=actor.user_id,
        outcome="SUCCESS",
        reason=f"APP_SIGN_IN:{app.name}",
        device_type=device.deviceType if device else None,
        platform=device.platform if device else None,
        app_version=device.appVersion if device else None,
        source_ip=ip,
    )
    ttl = settings.platform_admin_token_ttl_minutes
    if ttl is None:
        raise RuntimeError("Configured Security human access-token lifetime is unavailable")
    expires_at = now + timedelta(minutes=ttl)
    session_id = uuid4()
    device_id = device.deviceId if device is not None else uuid4()
    token = tokens.issue_human_token(
        HumanTokenClaims(
            user_id=actor.user_id, expires_at=expires_at, session_id=str(session_id), device_id=str(device_id)
        )
    )
    return {
        "accessToken": token,
        "expiresAtUtc": expires_at,
        "actorType": ActorType.USER.value,
        "isSuperAdmin": actor.is_super_admin,
        "sessionId": session_id,
        "deviceId": device_id,
        "email": store.email_of(actor.user_id),
    }
