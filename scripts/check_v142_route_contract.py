from verigence_security.main import app

schema = app.openapi()
paths = set(schema.get("paths", {}))

required = {
    "/security/v1/service/token",
    "/security/v1/authorization/check",
    "/security/v1/roles",
    "/security/v1/platform/role-defaults/{roleKey}",
    "/security/v1/tenants/{tenantId}/role-bundles/{roleKey}",
    "/security/v1/tenants/{tenantId}/users/{userId}/operating-role",
    "/security/v1/tenants/{tenantId}/groups",
    "/security/v1/tenants/{tenantId}/groups/{roleKey}",
    "/security/v1/tenants/{tenantId}/groups/{roleKey}/users",
    "/security/v1/tenants/{tenantId}/users/{userId}/admin-role/TenantAdmin",
    "/security/v1/modules/{moduleKey}/users/{userId}/admin-role/ModuleAdmin",
    "/security/v1/platform/modules/{moduleKey}/permissions",
    "/security/v1/platform/users",
    "/security/v1/platform/users/{userId}",
    "/security/v1/users/{userId}/status",
    "/security/v1/platform/tenants",
    "/security/v1/platform/tenants/{tenantId}",
}
missing = sorted(required - paths)
if missing:
    raise SystemExit(f"Missing Phase-1 Security target routes: {missing}")

# PlatformAdmin JWT control-plane endpoints no longer have a dependent caller and must
# remain retired. The older access/OAuth router is different: Audit Core dev still consumes
# it, so it stays as explicit temporary compatibility until that repo is migrated.
retired_exact = {
    "/security/v1/platform/bootstrap/claim",
    "/security/v1/platform/auth/login",
    "/security/v1/platform/me",
}
active_retired = sorted(retired_exact & paths)
if active_retired:
    raise SystemExit(f"Retired PlatformAdmin JWT routes are still active: {active_retired}")

retired_prefixes = (
    "/security/v1/admin/tenants/",
)
active_legacy_admin = sorted(
    path for path in paths if any(path.startswith(prefix) for prefix in retired_prefixes)
)
if active_legacy_admin:
    raise SystemExit(f"Retired arbitrary Tenant RBAC routes are still active: {active_legacy_admin}")

compatibility = {
    # Required by current Audit Core dev until it migrates to /security/v1/service/token
    # and Clerk-subject /authorization/check.
    "/oauth/token",
    # Older Security human token/session surface remains in the same compatibility router;
    # it is not part of the target Phase-1 model and must not be used by new code.
    "/security/v1/auth/login",
    "/security/v1/access-sessions",
    # Employee signup compatibility until the Clerk-first-party bind contract is fixed.
    "/security/v1/onboarding/users",
    "/security/v1/onboarding/users/{signupAttemptId}/verify-email",
    "/security/v1/onboarding/users/{signupAttemptId}/resend-email-code",
}
missing_compatibility = sorted(compatibility - paths)
if missing_compatibility:
    raise SystemExit(
        "Temporary compatibility routes disappeared before dependent callers migrated: "
        f"{missing_compatibility}"
    )

print("Phase-1 Security target + compatibility route contract PASSED")
