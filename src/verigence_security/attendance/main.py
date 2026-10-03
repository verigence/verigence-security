from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from verigence_security.attendance.api import router
from verigence_security.attendance.config import get_attendance_settings
from verigence_security.attendance.db import attendance_engine
from verigence_security.attendance.security import (
    AttendanceAuthenticationError,
    AttendanceAuthorizationError,
    AttendanceDependencyError,
)
from verigence_security.attendance.service import AttendanceRuleError


def create_app() -> FastAPI:
    settings = get_attendance_settings()
    application = FastAPI(
        title=settings.app_name,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    if settings.allowed_origin_list:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.allowed_origin_list,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
        )

    @application.exception_handler(AttendanceAuthenticationError)
    async def authentication_error(_: Request, exc: AttendanceAuthenticationError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"code": "ATTENDANCE_AUTHENTICATION_FAILED", "detail": str(exc)})

    @application.exception_handler(AttendanceAuthorizationError)
    async def authorization_error(_: Request, exc: AttendanceAuthorizationError) -> JSONResponse:
        return JSONResponse(status_code=403, content={"code": "ATTENDANCE_PERMISSION_DENIED", "detail": str(exc)})

    @application.exception_handler(AttendanceDependencyError)
    async def dependency_error(_: Request, exc: AttendanceDependencyError) -> JSONResponse:
        return JSONResponse(status_code=503, content={"code": "ATTENDANCE_DEPENDENCY_UNAVAILABLE", "detail": str(exc)})

    @application.exception_handler(AttendanceRuleError)
    async def rule_error(_: Request, exc: AttendanceRuleError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"code": exc.code, "detail": exc.detail})

    application.include_router(router)

    @application.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "attendance"}

    @application.get("/ready")
    def ready() -> dict[str, str]:
        with attendance_engine().connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ready", "service": "attendance"}

    return application


app = create_app()
