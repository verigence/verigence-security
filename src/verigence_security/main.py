from __future__ import annotations

import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.exceptions import RequestValidationError

from verigence_security.api.dependencies import correlation_header_parameter
from verigence_security.api.routes import (
    access,
    announcements,
    authorization,
    client_diagnostics,
    dev_mock,
    feature_access,
    health,
    hr_roles,
    human_observation,
    human_remember,
    jwks,
    legacy_onboarding_compat,
    login_activity,
    password_recovery,
    platform_admin,
    platform_modules,
    security_housekeeping,
    service_tokens,
    service_users,
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
from verigence_security.core.problem import (
    request_validation_error_handler,
    security_error_handler,
    unexpected_error_handler,
)

settings = get_settings()

@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Boot row, a beat a minute and CPU/memory for the SuperAdmin System Health page
    (product owner 2026-10-27); a clean stop is stamped on shutdown. Only against
    PostgreSQL: the shared platform_ops tables live there."""
    from verigence_security.db.session import _is_postgresql, build_engine
    from verigence_security.platform_heartbeat import start_platform_heartbeat

    settings = get_settings()
    stop = threading.Event()
    heartbeat = None
    if settings.database_url and _is_postgresql(settings.database_url):
        heartbeat = start_platform_heartbeat(build_engine(settings), "security", stop)
    try:
        yield
    finally:
        stop.set()
        if heartbeat is not None:
            heartbeat.join(timeout=5)


app = FastAPI(
    title="Verigence Security API",
    version="0.3.0",
    description=(
        "Phase-1 Security: Security-only Clerk-backed human authentication, "
        "Security-owned authorization, and Security-issued ServiceIntegration machine tokens"
    ),
    dependencies=[Depends(correlation_header_parameter)],
    lifespan=_lifespan,
)
app.add_middleware(CorrelationIdMiddleware)
app.add_exception_handler(RequestValidationError, request_validation_error_handler)
app.add_exception_handler(SecurityError, security_error_handler)
app.add_exception_handler(Exception, unexpected_error_handler)
app.include_router(health.router)
app.include_router(jwks.router)
# access.router contains the canonical /security/v1/auth/login plus the deprecated
# /security/v1/access-sessions bridge. oauth_router is retained only because current Audit Core
# dev still calls /oauth/token; it is not the target machine-token contract.
app.include_router(access.oauth_router)
app.include_router(access.router)
app.include_router(human_remember.router)
app.include_router(human_observation.router)
app.include_router(password_recovery.router)
app.include_router(service_tokens.router)
app.include_router(service_users.router)
app.include_router(authorization.router)
app.include_router(hr_roles.router)
app.include_router(feature_access.router)
app.include_router(announcements.router)
app.include_router(client_diagnostics.router)
app.include_router(login_activity.router)
app.include_router(platform_admin.router)
app.include_router(security_housekeeping.router)
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
