from verigence_security.api.routes import access, tenant_groups, tenant_roles

# `access.router` is already registered by the application. The child route objects
# carry their complete `/security/v1/admin/...` paths, so attach them directly without
# applying the access router's `/security/v1` prefix a second time.
access.router.routes.extend(tenant_groups.router.routes)
access.router.routes.extend(tenant_roles.router.routes)
