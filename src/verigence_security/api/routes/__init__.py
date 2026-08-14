from verigence_security.api.routes import access, tenant_groups, tenant_roles

# `access.router` is already registered by the application. The child route objects
# carry their complete `/security/v1/admin/...` paths, so attach them directly without
# applying the access router's `/security/v1` prefix a second time.
access.router.routes.extend(tenant_groups.router.routes)
access.router.routes.extend(tenant_roles.router.routes)

# v1.4.2 makes human USER onboarding Platform-global and one-time. The v1.4 Tenant
# invitation/self-onboarding functions remain in source only as migration/history debt; they are
# deliberately removed from the active FastAPI route table so a second Tenant-scoped identity
# lifecycle cannot continue running alongside the global model.
_RETIRED_TENANT_ONBOARDING_PREFIXES = (
    "/security/v1/platform/tenants/{tenantId}/owner-invitations",
    "/security/v1/platform/tenants/{tenantId}/self-onboarding-token",
    "/security/v1/admin/tenants/{tenantId}/invitations",
    "/security/v1/onboarding/invitations/",
    "/security/v1/onboarding/tenants/",
    "/security/v1/admin/tenants/{tenantId}/self-onboarding-requests",
)
access.router.routes[:] = [
    route
    for route in access.router.routes
    if not any(
        getattr(route, "path", "").startswith(prefix)
        for prefix in _RETIRED_TENANT_ONBOARDING_PREFIXES
    )
]
