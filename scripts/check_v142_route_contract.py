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

retired_exact = {
    "/oauth/token",
    "/security/v1/auth/login",
    "/security/v1/access-sessions",
    "/security/v1/platform/bootstrap/claim",
    "/security/v1/platform/auth/login",
    "/security/v1/platform/me",
}
active_retired = sorted(retired_exact & paths)
if active_retired:
    raise SystemExit(f"Retired human/OAuth token routes are still active: {active_retired}")

retired_prefixes = (
    "/security/v1/admin/tenants/",
)
active_legacy_admin = sorted(
    path for path in paths if any(path.startswith(prefix) for prefix in retired_prefixes)
)
if active_legacy_admin:
    raise SystemExit(f"Retired arbitrary Tenant RBAC routes are still active: {active_legacy_admin}")

# Temporary compatibility until the Clerk-first-party authenticated bind URL/contract is
# explicitly fixed. These are intentionally deprecated and must not be mistaken for the
# target onboarding model.
compatibility = {
    "/security/v1/onboarding/users",
    "/security/v1/onboarding/users/{signupAttemptId}/verify-email",
    "/security/v1/onboarding/users/{signupAttemptId}/resend-email-code",
}
missing_compatibility = sorted(compatibility - paths)
if missing_compatibility:
    raise SystemExit(
        "Temporary onboarding compatibility routes disappeared before bind replacement: "
        f"{missing_compatibility}"
    )

print("Phase-1 Security target route contract PASSED")
