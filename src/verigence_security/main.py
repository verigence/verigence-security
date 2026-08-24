from __future__ import annotations

from fastapi import Depends, FastAPI

from verigence_security.api.dependencies import correlation_header_parameter
from verigence_security.api.routes import (
    access,
    authorization,
    dev_mock,
    health,
    human_refresh,
    jwks,
    legacy_onboarding_compat,
    password_recovery,
    platform_admin,
    platform_modules,
    service_tokens,
    tenant_activation_compensation,
    v2_admin_roles,
    v2_groups,
    v2_rbac,
    v2_user_admin,
    v2_user_lifecycle,
)
from verigence_security.config import get_settings
from verigence_security.core.correlation import CorrelationIdMiddleware
from verigence_security.core.errors import SecurityError
from verigence_security.core.observability import configure_observability
from verigence_security.core.problem import security_error_handler, unexpected_error_handler

settings = get_settings()

app = FastAPI(
    title="Verigence Security API",
    version="0.3.0",
    description=(
        "Phase-1 Security: Security-only Clerk-backed human authentication, "
        "Security-owned authorization, and Security-issued ServiceIntegration machine tokens"
    ),
    dependencies=[Depends(correlation_header_parameter)],
)
app.add_middleware(CorrelationIdMiddleware)
app.add_exception_handler(SecurityError, security_error_handler)
app.add_exception_handler(Exception, unexpected_error_handler)
app.include_router(health.router)
app.include_router(jwks.router)
# access.router contains the canonical /security/v1/auth/login plus the deprecated
# /security/v1/access-sessions bridge. oauth_router is retained only because current Audit Core
# dev still calls /oauth/token; it is not the target machine-token contract.
app.include_router(access.oauth_router)
app.include_router(access.router)
app.include_router(human_refresh.router)
app.include_router(password_recovery.router)
app.include_router(service_tokens.router)
app.include_router(authorization.router)
app.include_router(platform_admin.router)
app.include_router(tenant_activation_compensation.router)
app.include_router(platform_modules.router)
app.include_router(v2_user_admin.router)
app.include_router(v2_rbac.router)
app.include_router(v2_groups.router)
app.include_router(v2_admin_roles.router)
app.include_router(v2_user_lifecycle.router)
app.include_router(legacy_onboarding_compat.router)
if settings.dev_mock_auth_enabled:
    app.include_router(dev_mock.router)

# Disabled by default. When enabled, exporters are batched/bounded and never awaited by business
# handlers. No authentication, authorization, token or route contract depends on telemetry.
configure_observability(app, settings)
