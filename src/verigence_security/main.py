from __future__ import annotations

from fastapi import Depends, FastAPI

from verigence_security.api.dependencies import correlation_header_parameter
from verigence_security.api.routes import (
    access,
    dev_mock,
    global_users,
    health,
    jwks,
    platform_admin,
    platform_modules,
    tenant_groups,
    tenant_roles,
)
from verigence_security.config import get_settings
from verigence_security.core.correlation import CorrelationIdMiddleware
from verigence_security.core.errors import SecurityError
from verigence_security.core.problem import security_error_handler, unexpected_error_handler

settings = get_settings()

app = FastAPI(
    title="Verigence Security API",
    version="0.3.0",
    description=(
        "Security runtime plus Admin Control Plane v1.4, Clerk identity boundary v1.4.1, "
        "and Platform-global one-time USER onboarding v1.4.2"
    ),
    dependencies=[Depends(correlation_header_parameter)],
)
app.add_middleware(CorrelationIdMiddleware)
app.add_exception_handler(SecurityError, security_error_handler)
app.add_exception_handler(Exception, unexpected_error_handler)
app.include_router(health.router)
app.include_router(jwks.router)
app.include_router(access.router)
app.include_router(tenant_groups.router)
app.include_router(tenant_roles.router)
app.include_router(platform_admin.router)
app.include_router(platform_modules.router)
app.include_router(global_users.router)
if settings.dev_mock_auth_enabled:
    app.include_router(dev_mock.router)
