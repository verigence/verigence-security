from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class SecurityAdminRepository:
    """Persistence primitives for deterministic Security administration contracts."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def tenant(self, tenant_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc
                FROM security.tenants
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        return dict(row) if row else None

    def security_policy(self, tenant_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.tenant_security_policies
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        return dict(row) if row else None

    def upsert_security_policy(
        self,
        *,
        tenant_id: str,
        max_active_devices_per_user: int,
        max_geo_accuracy_meters: float,
        max_geo_age_seconds: int,
        geo_revalidation_interval_seconds: int,
        access_token_ttl_minutes: int,
        machine_token_ttl_minutes: int,
        session_idle_timeout_minutes: int,
        session_max_duration_minutes: int,
        vpn_detected_action: str,
        vpn_unknown_action: str,
        configuration_version: int,
        status: str,
        updated_by_user_id: str,
        updated_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_security_policies
                (tenant_id,max_active_devices_per_user,max_geo_accuracy_meters,
                 max_geo_age_seconds,geo_revalidation_interval_seconds,
                 access_token_ttl_minutes,machine_token_ttl_minutes,
                 session_idle_timeout_minutes,session_max_duration_minutes,
                 vpn_detected_action,vpn_unknown_action,configuration_version,status,
                 updated_by_user_id,updated_at_utc)
                VALUES
                (:tenant_id,:max_active_devices_per_user,:max_geo_accuracy_meters,
                 :max_geo_age_seconds,:geo_revalidation_interval_seconds,
                 :access_token_ttl_minutes,:machine_token_ttl_minutes,
                 :session_idle_timeout_minutes,:session_max_duration_minutes,
                 :vpn_detected_action,:vpn_unknown_action,:configuration_version,:status,
                 :updated_by_user_id,:updated_at)
                ON CONFLICT (tenant_id) DO UPDATE SET
                  max_active_devices_per_user=EXCLUDED.max_active_devices_per_user,
                  max_geo_accuracy_meters=EXCLUDED.max_geo_accuracy_meters,
                  max_geo_age_seconds=EXCLUDED.max_geo_age_seconds,
                  geo_revalidation_interval_seconds=EXCLUDED.geo_revalidation_interval_seconds,
                  access_token_ttl_minutes=EXCLUDED.access_token_ttl_minutes,
                  machine_token_ttl_minutes=EXCLUDED.machine_token_ttl_minutes,
                  session_idle_timeout_minutes=EXCLUDED.session_idle_timeout_minutes,
                  session_max_duration_minutes=EXCLUDED.session_max_duration_minutes,
                  vpn_detected_action=EXCLUDED.vpn_detected_action,
                  vpn_unknown_action=EXCLUDED.vpn_unknown_action,
                  configuration_version=EXCLUDED.configuration_version,
                  status=EXCLUDED.status,
                  updated_by_user_id=EXCLUDED.updated_by_user_id,
                  updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "tenant_id": tenant_id,
                "max_active_devices_per_user": max_active_devices_per_user,
                "max_geo_accuracy_meters": max_geo_accuracy_meters,
                "max_geo_age_seconds": max_geo_age_seconds,
                "geo_revalidation_interval_seconds": geo_revalidation_interval_seconds,
                "access_token_ttl_minutes": access_token_ttl_minutes,
                "machine_token_ttl_minutes": machine_token_ttl_minutes,
                "session_idle_timeout_minutes": session_idle_timeout_minutes,
                "session_max_duration_minutes": session_max_duration_minutes,
                "vpn_detected_action": vpn_detected_action,
                "vpn_unknown_action": vpn_unknown_action,
                "configuration_version": configuration_version,
                "status": status,
                "updated_by_user_id": updated_by_user_id,
                "updated_at": updated_at,
            },
        )

    def retention_policy(self, tenant_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT *
                FROM security.security_retention_policies
                WHERE tenant_id=:tenant_id
                """
            ),
            {"tenant_id": tenant_id},
        ).mappings().first()
        return dict(row) if row else None

    def upsert_retention_policy(
        self,
        *,
        tenant_id: str,
        access_context_retention_days: int,
        access_session_retention_days: int,
        security_event_retention_days: int,
        status: str,
        updated_by_user_id: str,
        updated_at: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.security_retention_policies
                (tenant_id,access_context_retention_days,access_session_retention_days,
                 security_event_retention_days,status,updated_by_user_id,updated_at_utc)
                VALUES
                (:tenant_id,:access_context_retention_days,:access_session_retention_days,
                 :security_event_retention_days,:status,:updated_by_user_id,:updated_at)
                ON CONFLICT (tenant_id) DO UPDATE SET
                  access_context_retention_days=EXCLUDED.access_context_retention_days,
                  access_session_retention_days=EXCLUDED.access_session_retention_days,
                  security_event_retention_days=EXCLUDED.security_event_retention_days,
                  status=EXCLUDED.status,
                  updated_by_user_id=EXCLUDED.updated_by_user_id,
                  updated_at_utc=EXCLUDED.updated_at_utc
                """
            ),
            {
                "tenant_id": tenant_id,
                "access_context_retention_days": access_context_retention_days,
                "access_session_retention_days": access_session_retention_days,
                "security_event_retention_days": security_event_retention_days,
                "status": status,
                "updated_by_user_id": updated_by_user_id,
                "updated_at": updated_at,
            },
        )

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
