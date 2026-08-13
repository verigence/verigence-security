from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI

from verigence_security.api.dependencies import correlation_header_parameter
from verigence_security.api.routes import access, dev_mock, health, jwks, platform_admin
from verigence_security.config import get_settings
from verigence_security.core.correlation import CorrelationIdMiddleware
from verigence_security.core.errors import SecurityError
from verigence_security.core.problem import security_error_handler, unexpected_error_handler
from verigence_security.db.session import build_session_factory
from verigence_security.services.platform_admin import PlatformBootstrapService

settings = get_settings()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if settings.platform_bootstrap_enabled:
        factory = build_session_factory(settings)
        if factory is None:
            raise RuntimeError("Database is required for Platform Super Admin bootstrap")
        with factory() as session:
            PlatformBootstrapService(session, settings).bootstrap_if_needed()
    yield


app = FastAPI(
    title="Verigence Security API",
    version="0.2.0",
    description="Security runtime plus Admin Control Plane v1.4 implementation",
    dependencies=[Depends(correlation_header_parameter)],
    lifespan=lifespan,
)
app.add_middleware(CorrelationIdMiddleware)
app.add_exception_handler(SecurityError, security_error_handler)
app.add_exception_handler(Exception, unexpected_error_handler)
app.include_router(health.router)
app.include_router(jwks.router)
app.include_router(access.router)
app.include_router(platform_admin.router)
if settings.dev_mock_auth_enabled:
    app.include_router(dev_mock.router)
