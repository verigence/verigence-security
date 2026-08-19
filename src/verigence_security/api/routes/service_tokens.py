from __future__ import annotations

import base64
from datetime import UTC, datetime
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.service_token_schemas import ServiceTokenResponse
from verigence_security.config import Settings, get_settings
from verigence_security.core.errors import security_error
from verigence_security.repositories.service_integration_repository import ServiceIntegrationRepository
from verigence_security.services.service_integration_tokens import ServiceIntegrationTokenService
from verigence_security.services.token_service import TokenService

router = APIRouter(prefix="/security/v1", tags=["ServiceIntegration"])


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


def _form_values(body: bytes) -> dict[str, str]:
    try:
        values = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="Request body is not valid form data") from exc
    return {key: items[-1] for key, items in values.items() if items}


@router.post("/service/token", response_model=ServiceTokenResponse)
async def issue_service_token(
    request: Request,
    session: Session = Depends(platform_session),
    settings: Settings = Depends(get_settings),
) -> ServiceTokenResponse:
    client = _basic_client(request)
    if client is None:
        raise security_error("MACHINE_CREDENTIAL_INVALID")
    client_id, client_secret = client

    form = _form_values(await request.body())
    audience = form.get("audience", "").strip()
    if not audience:
        raise HTTPException(status_code=400, detail="audience is required")

    service = ServiceIntegrationTokenService(
        ServiceIntegrationRepository(session),
        TokenService(settings),
    )
    try:
        result = service.issue(
            client_id=client_id,
            client_secret=client_secret,
            audience=audience,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    expires_in = max(0, int((result.expires_at_utc - datetime.now(UTC)).total_seconds()))
    return ServiceTokenResponse(
        accessToken=result.access_token,
        expiresIn=expires_in,
        audience=result.audience,
    )
