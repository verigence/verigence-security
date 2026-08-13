from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from verigence_security.repositories.admin_repository import SecurityAdminRepository


@dataclass(frozen=True, slots=True)
class TenantSecurityPolicyConfiguration:
    max_active_devices_per_user: int
    max_geo_accuracy_meters: float
    max_geo_age_seconds: int
    geo_revalidation_interval_seconds: int
    access_token_ttl_minutes: int
    machine_token_ttl_minutes: int
    session_idle_timeout_minutes: int
    session_max_duration_minutes: int
    vpn_detected_action: str
    vpn_unknown_action: str
    configuration_version: int
    status: str


@dataclass(frozen=True, slots=True)
class SecurityRetentionPolicyConfiguration:
    access_context_retention_days: int
    access_session_retention_days: int
    security_event_retention_days: int
    status: str


@dataclass(frozen=True, slots=True)
class TenantConfigurationSnapshot:
    tenant_id: str
    tenant_status: str
    security_policy_status: str | None
    retention_policy_status: str | None


class TenantConfigurationService:
    """Internal Phase 5 administration for approved Tenant configuration tables."""

    def __init__(self, repository: SecurityAdminRepository) -> None:
        self.repository = repository

    def configure_security_policy(
        self,
        *,
        tenant_id: str,
        configuration: TenantSecurityPolicyConfiguration,
        updated_by_user_id: str,
        updated_at: datetime,
    ) -> bool:
        try:
            if self.repository.tenant(tenant_id) is None:
                self.repository.rollback()
                return False
            self.repository.upsert_security_policy(
                tenant_id=tenant_id,
                max_active_devices_per_user=configuration.max_active_devices_per_user,
                max_geo_accuracy_meters=configuration.max_geo_accuracy_meters,
                max_geo_age_seconds=configuration.max_geo_age_seconds,
                geo_revalidation_interval_seconds=(
                    configuration.geo_revalidation_interval_seconds
                ),
                access_token_ttl_minutes=configuration.access_token_ttl_minutes,
                machine_token_ttl_minutes=configuration.machine_token_ttl_minutes,
                session_idle_timeout_minutes=configuration.session_idle_timeout_minutes,
                session_max_duration_minutes=configuration.session_max_duration_minutes,
                vpn_detected_action=configuration.vpn_detected_action,
                vpn_unknown_action=configuration.vpn_unknown_action,
                configuration_version=configuration.configuration_version,
                status=configuration.status,
                updated_by_user_id=updated_by_user_id,
                updated_at=updated_at,
            )
            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise

    def configure_retention_policy(
        self,
        *,
        tenant_id: str,
        configuration: SecurityRetentionPolicyConfiguration,
        updated_by_user_id: str,
        updated_at: datetime,
    ) -> bool:
        try:
            if self.repository.tenant(tenant_id) is None:
                self.repository.rollback()
                return False
            self.repository.upsert_retention_policy(
                tenant_id=tenant_id,
                access_context_retention_days=(
                    configuration.access_context_retention_days
                ),
                access_session_retention_days=(
                    configuration.access_session_retention_days
                ),
                security_event_retention_days=(
                    configuration.security_event_retention_days
                ),
                status=configuration.status,
                updated_by_user_id=updated_by_user_id,
                updated_at=updated_at,
            )
            self.repository.commit()
            return True
        except Exception:
            self.repository.rollback()
            raise

    def snapshot(self, tenant_id: str) -> TenantConfigurationSnapshot | None:
        tenant = self.repository.tenant(tenant_id)
        if tenant is None:
            return None
        security_policy = self.repository.security_policy(tenant_id)
        retention_policy = self.repository.retention_policy(tenant_id)
        return TenantConfigurationSnapshot(
            tenant_id=tenant_id,
            tenant_status=str(tenant["status"]),
            security_policy_status=(
                str(security_policy["status"]) if security_policy is not None else None
            ),
            retention_policy_status=(
                str(retention_policy["status"]) if retention_policy is not None else None
            ),
        )
