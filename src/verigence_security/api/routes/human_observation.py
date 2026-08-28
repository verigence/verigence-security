from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends

from verigence_security.api.dependencies import bearer_token, repository, source_ip, token_service
from verigence_security.api.schemas import (
    HumanSessionObservationRequest,
    HumanSessionObservationResponse,
)
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.human_observation_repository import HumanObservationRepository
from verigence_security.repositories.security_repository import SecurityRepository
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1/auth", tags=["Runtime Access"])


def _uuid_claim(claims: dict[str, object], name: str) -> UUID:
    value = claims.get(name)
    if not isinstance(value, str):
        raise security_error("AUTH_TOKEN_INVALID")
    try:
        return UUID(value)
    except ValueError as exc:
        raise security_error("AUTH_TOKEN_INVALID") from exc


def _expiry(claims: dict[str, object]) -> datetime:
    value = claims.get("exp")
    if not isinstance(value, (int, float)):
        raise security_error("AUTH_TOKEN_INVALID")
    return datetime.fromtimestamp(float(value), UTC)


@router.post("/session-observation", response_model=HumanSessionObservationResponse)
def observe_human_session(
    body: HumanSessionObservationRequest,
    authorization_token: str = Depends(bearer_token),
    settings: Settings = Depends(get_settings),
    repo: SecurityRepository = Depends(repository),
    tokens: TokenService = Depends(token_service),
    ip: str = Depends(source_ip),
) -> dict[str, object]:
    """Persist post-login device/session/geo evidence without participating in login latency.

    The Web/Mobile client intentionally invokes this after it has accepted the Security login and
    begun normal navigation. Observation-mode failures therefore do not become login failures.
    """

    claims = tokens.verify_human_token(authorization_token)
    user_id = str(claims["sub"])
    session_id = _uuid_claim(claims, "session_id")
    device_id = _uuid_claim(claims, "device_id")
    token_expires_at = _expiry(claims)
    now = datetime.now(UTC)

    observation = HumanObservationRepository(repo.s)
    registration = observation.register_observation_session(
        user_id=user_id,
        session_id=session_id,
        device_id=device_id,
        device_type=body.deviceType,
        platform=body.platform,
        device_name=body.deviceName,
        device_model=body.deviceModel,
        os_version=body.osVersion,
        browser_name=body.browserName,
        browser_version=body.browserVersion,
        app_version=body.appVersion,
        source_ip=ip,
        token_expires_at=token_expires_at,
        now=now,
    )

    geo_recorded = False
    if body.geoStatus != "PENDING" or body.geo is not None:
        if body.geoStatus == "AVAILABLE" and body.geo is None:
            raise security_error("GEO_UNAVAILABLE")
        geo = body.geo
        geo_recorded = observation.record_geo(
            user_id=user_id,
            session_id=session_id,
            device_id=device_id,
            geo_status=body.geoStatus,
            latitude=geo.latitude if geo is not None else None,
            longitude=geo.longitude if geo is not None else None,
            accuracy_meters=geo.accuracyMeters if geo is not None else None,
            geo_source=geo.source if geo is not None else None,
            captured_at=geo.capturedAt if geo is not None else None,
            now=datetime.now(UTC),
        )

    active_device_count = int(registration["active_device_count"])
    device_limit = settings.human_device_observation_limit
    return {
        "observationMode": "OBSERVE",
        "previousSessionSuperseded": bool(registration["previous_session_superseded"]),
        "previousSessionDifferentDevice": bool(
            registration["previous_session_different_device"]
        ),
        "activeDeviceCount": active_device_count,
        "deviceLimit": device_limit,
        "deviceLimitExceeded": active_device_count > device_limit,
        "geoRecorded": geo_recorded,
    }
