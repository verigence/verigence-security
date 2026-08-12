from __future__ import annotations

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from verigence_security.config import Settings, get_settings
from verigence_security.db.session import database_is_ready
from verigence_security.services.token_service import TokenService

router = APIRouter(tags=["Health"])


@router.get("/health/live")
def live() -> dict[str, str]:
    return {"status": "live"}


@router.get("/health/ready")
def ready(settings: Settings = Depends(get_settings)) -> JSONResponse:
    database_ready = database_is_ready(settings)
    signing_ready = TokenService(settings).signing_key_ready()
    ready_now = database_ready and signing_ready
    return JSONResponse(
        status_code=200 if ready_now else 503,
        content={
            "status": "ready" if ready_now else "not_ready",
            "environment": settings.app_env.value,
            "databaseReady": database_ready,
            "signingKeyReady": signing_ready,
        },
    )
