from __future__ import annotations

from fastapi import Depends, FastAPI

from verigence_security.api.dependencies import correlation_header_parameter
from verigence_security.api.routes import (
    access,
    authorization,
    dev_mock,
    global_users,
    health,
    jwks,
    platform_admin,
    platform_modules,
    service_tokens,
    v2_admin_roles,
    v2_groups,
    v2_rbac,
    v2_user_lifecycle,
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
        "Security runtime, Admin Control Plane v1.4, Platform-global USER onboarding, "
        "and backend-only Clerk authentication/email OTP boundary v1.4.8"
    ),
    dependencies=[Depends(correlation_header_parameter)],
)
app.add_middleware(CorrelationIdMiddleware)
app.add_exception_handler(SecurityError, security_error_handler)
app.add_exception_handler(Exception, unexpected_error_handler)
app.include_router(health.router)
app.include_router(jwks.router)
app.include_router(access.oauth_router)
app.include_router(access.router)
app.include_router(service_tokens.router)
app.include_router(authorization.router)
app.include_router(platform_admin.router)
app.include_router(platform_modules.router)
app.include_router(global_users.router)
app.include_router(v2_rbac.router)
app.include_router(v2_groups.router)
app.include_router(v2_admin_roles.router)
app.include_router(v2_user_lifecycle.router)
if settings.dev_mock_auth_enabled:
    app.include_router(dev_mock.router)
