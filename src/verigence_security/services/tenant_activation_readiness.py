from __future__ import annotations

from dataclasses import dataclass

from verigence_security.repositories.admin_repository import SecurityAdminRepository


@dataclass(frozen=True, slots=True)
class ActivationPrerequisite:
    key: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class TenantActivationReadiness:
    tenant_id: str
    tenant_status: str
    prerequisites: tuple[ActivationPrerequisite, ...]
    known_prerequisites_pass: bool
    prerequisite_catalogue_complete: bool
    activation_allowed: bool


class TenantActivationReadinessService:
    """SEC-032 foundation using only prerequisites frozen by active approved sources."""

    def __init__(self, repository: SecurityAdminRepository) -> None:
        self.repository = repository

    def evaluate(self, tenant_id: str) -> TenantActivationReadiness | None:
        tenant = self.repository.tenant(tenant_id)
        if tenant is None:
            return None

        security_policy = self.repository.security_policy(tenant_id)
        retention_policy = self.repository.retention_policy(tenant_id)

        prerequisites = (
            ActivationPrerequisite(
                key="SECURITY_POLICY_ACTIVE",
                passed=(
                    security_policy is not None and security_policy["status"] == "ACTIVE"
                ),
                detail=(
                    "ACTIVE Tenant Security Policy configured"
                    if security_policy is not None and security_policy["status"] == "ACTIVE"
                    else "ACTIVE Tenant Security Policy is required"
                ),
            ),
            ActivationPrerequisite(
                key="SECURITY_RETENTION_POLICY_ACTIVE",
                passed=(
                    retention_policy is not None and retention_policy["status"] == "ACTIVE"
                ),
                detail=(
                    "ACTIVE Security retention policy configured"
                    if retention_policy is not None and retention_policy["status"] == "ACTIVE"
                    else "ACTIVE Security retention policy is required by SEC-037"
                ),
            ),
        )
        known_pass = all(item.passed for item in prerequisites)

        # SEC-032 requires the complete prerequisite list before activation can proceed.
        # Active repository sources do not currently enumerate that complete catalogue.
        return TenantActivationReadiness(
            tenant_id=tenant_id,
            tenant_status=str(tenant["status"]),
            prerequisites=prerequisites,
            known_prerequisites_pass=known_pass,
            prerequisite_catalogue_complete=False,
            activation_allowed=False,
        )
