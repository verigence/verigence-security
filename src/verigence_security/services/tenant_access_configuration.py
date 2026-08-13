from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time

from sqlalchemy.orm import Session

from verigence_security.repositories.admin_repository import SecurityAdminRepository
from verigence_security.repositories.location_admin_repository import LocationAdminRepository
from verigence_security.repositories.schedule_admin_repository import ScheduleAdminRepository


@dataclass(frozen=True, slots=True)
class TenantLocationConfiguration:
    location_id: str
    location_code: str
    location_name: str
    location_type: str
    latitude: float
    longitude: float
    allowed_radius_meters: int
    timezone_iana: str
    address_line1: str | None
    city: str | None
    state_region: str | None
    country_code: str | None
    postal_code: str | None
    status: str


@dataclass(frozen=True, slots=True)
class AccessScheduleWindowConfiguration:
    schedule_window_id: str
    iso_day_of_week: int
    start_local_time: time
    end_local_time: time
    crosses_midnight: bool
    status: str


@dataclass(frozen=True, slots=True)
class AccessScheduleConfiguration:
    schedule_id: str
    schedule_key: str
    schedule_name: str
    status: str
    windows: tuple[AccessScheduleWindowConfiguration, ...]


class TenantAccessConfigurationService:
    """Internal administration for approved Tenant location/schedule tables."""

    def __init__(self, session: Session) -> None:
        self.admin = SecurityAdminRepository(session)
        self.locations = LocationAdminRepository(session)
        self.schedules = ScheduleAdminRepository(session)

    def configure_location(
        self,
        *,
        tenant_id: str,
        configuration: TenantLocationConfiguration,
        now: datetime,
    ) -> bool:
        try:
            if self.admin.tenant(tenant_id) is None:
                self.admin.rollback()
                return False
            self.locations.upsert_location(
                location_id=configuration.location_id,
                tenant_id=tenant_id,
                location_code=configuration.location_code,
                location_name=configuration.location_name,
                location_type=configuration.location_type,
                latitude=configuration.latitude,
                longitude=configuration.longitude,
                allowed_radius_meters=configuration.allowed_radius_meters,
                timezone_iana=configuration.timezone_iana,
                address_line1=configuration.address_line1,
                city=configuration.city,
                state_region=configuration.state_region,
                country_code=configuration.country_code,
                postal_code=configuration.postal_code,
                status=configuration.status,
                now=now,
            )
            self.locations.commit()
            return True
        except Exception:
            self.locations.rollback()
            raise

    def configure_schedule(
        self,
        *,
        tenant_id: str,
        configuration: AccessScheduleConfiguration,
        now: datetime,
    ) -> bool:
        try:
            if self.admin.tenant(tenant_id) is None:
                self.admin.rollback()
                return False
            self.schedules.upsert_schedule(
                schedule_id=configuration.schedule_id,
                tenant_id=tenant_id,
                schedule_key=configuration.schedule_key,
                schedule_name=configuration.schedule_name,
                status=configuration.status,
                now=now,
            )
            for window in configuration.windows:
                self.schedules.upsert_window(
                    schedule_window_id=window.schedule_window_id,
                    tenant_id=tenant_id,
                    schedule_id=configuration.schedule_id,
                    iso_day_of_week=window.iso_day_of_week,
                    start_local_time=window.start_local_time,
                    end_local_time=window.end_local_time,
                    crosses_midnight=window.crosses_midnight,
                    status=window.status,
                )
            self.schedules.commit()
            return True
        except Exception:
            self.schedules.rollback()
            raise
