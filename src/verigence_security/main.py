from __future__ import annotations

from fastapi import Depends, FastAPI

from verigence_security.api.dependencies import correlation_header_parameter
from verigence_security.api.routes import access, dev_mock, health, jwks, platform_admin
from verigence_security.config import get_settings
from verigence_security.core.correlation import CorrelationIdMiddleware
from verigence_security.core.errors import SecurityError
from verigence_security.core.problem import security_error_handler, unexpected_error_handler

settings = get_settings()
app = FastAPI(
    title="Verigence Security API",
    version="0.1.0",
    description="Implementation baseline grounded in Security Design v1.3",
    dependencies=[Depends(correlation_header_parameter)],
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
