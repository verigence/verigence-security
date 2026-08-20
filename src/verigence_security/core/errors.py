from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class SecurityError(Exception):
    code: str
    status_code: int
    title: str
    detail: str | None = None

    def __str__(self) -> str:
        return self.detail or self.title


# Normative v1.3 error / denial catalogue. Keep codes stable; clients must not parse detail text.
ERRORS: dict[str, tuple[int, str]] = {
    "AUTH_TOKEN_INVALID": (401, "Authentication token is invalid"),
    "AUTH_TOKEN_EXPIRED": (401, "Authentication token has expired"),
    "USER_NOT_ONBOARDED": (403, "User is not onboarded"),
    "USER_PENDING_APPROVAL": (403, "User activation is pending administrator approval"),
    "USER_NOT_ACTIVE": (403, "User is not active"),
    "TENANT_NOT_ACTIVE": (403, "Tenant is not active"),
    "TENANT_SECURITY_NOT_READY": (403, "Tenant security configuration is not ready"),
    "TENANT_MEMBERSHIP_REQUIRED": (403, "Tenant membership is required"),
    "TENANT_MEMBERSHIP_INACTIVE": (403, "Tenant membership is inactive"),
    "DEVICE_NOT_REGISTERED": (403, "Device is not registered"),
    "DEVICE_APPROVAL_REQUIRED": (403, "Device approval is required"),
    "DEVICE_NOT_ACTIVE": (403, "Device is not active"),
    "DEVICE_LIMIT_REACHED": (409, "Device limit reached"),
    "GEO_REQUIRED": (403, "Geo context is required"),
    "GEO_PERMISSION_DENIED": (403, "Geo permission was denied"),
    "GEO_UNAVAILABLE": (403, "Geo context is unavailable"),
    "GEO_STALE": (403, "Geo context is stale"),
    "GEO_ACCURACY_INSUFFICIENT": (403, "Geo accuracy is insufficient"),
    "LOCATION_NOT_ASSIGNED": (403, "No active assigned location"),
    "LOCATION_NOT_ALLOWED": (403, "Current location is not allowed"),
    "ACCESS_OUTSIDE_ALLOWED_TIME": (403, "Access is outside allowed time"),
    "ACCESS_SCHEDULE_MISSING": (403, "Access schedule is missing"),
    "VPN_ACCESS_DENIED": (403, "VPN access is denied"),
    "NETWORK_RISK_UNKNOWN_DENIED": (403, "Unknown network risk is denied"),
    "ROLE_REQUIRED": (403, "An active role is required"),
    "PERMISSION_DENIED": (403, "Permission denied"),
    "IDENTITY_PROVIDER_UNAVAILABLE": (503, "Identity provider is unavailable"),
    "DATABASE_UNAVAILABLE": (503, "Security database is unavailable"),
    "SIGNING_KEY_UNAVAILABLE": (503, "Security signing key is unavailable"),
    "ACCESS_SESSION_ALREADY_ACTIVE": (409, "Access session is already active"),
    "ACCESS_SESSION_CONTEXT_CONFLICT": (409, "Active access session context conflicts"),
    "SESSION_REVOKED": (401, "Access session is revoked"),
    "PRINCIPAL_NOT_ACTIVE": (403, "Security principal is not active"),
    "PRINCIPAL_TENANT_SCOPE_REQUIRED": (403, "Principal Tenant scope is required"),
    "MACHINE_CREDENTIAL_INVALID": (401, "Machine credential is invalid"),
    "MACHINE_CREDENTIAL_EXPIRED": (401, "Machine credential has expired"),
    "ACTIVATION_REQUIREMENTS_NOT_MET": (409, "Tenant activation requirements are not met"),
    "ACTOR_TYPE_NOT_ALLOWED": (403, "Actor type is not allowed for this operation"),
    "TENANT_OFFBOARDING": (403, "Tenant is offboarding or offboarded"),
    "GEO_INTEGRITY_FAILED": (403, "Geo integrity check failed"),
    "CORRELATION_ID_INVALID": (400, "Invalid correlation ID"),
    "RETENTION_POLICY_NOT_CONFIGURED": (409, "Security retention policy is not configured"),
    "TENANT_ALREADY_OFFBOARDED": (409, "Tenant is already offboarded"),
}


def security_error(code: str, detail: str | None = None) -> SecurityError:
    status, title = ERRORS.get(code, (500, "Security service error"))
    return SecurityError(code=code, status_code=status, title=title, detail=detail)
