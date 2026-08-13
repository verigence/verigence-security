from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session


class LocationAdminRepository:
    def __init__(self, session: Session) -> None:
        self.s = session

    def tenant_exists(self, tenant_id: str) -> bool:
        row = self.s.execute(
            text("SELECT 1 FROM security.tenants WHERE tenant_id=:tenant_id"),
            {"tenant_id": tenant_id},
        ).first()
        return row is not None

    def upsert_location(
        self,
        *,
        location_id: str,
        tenant_id: str,
        location_code: str,
        location_name: str,
        location_type: str,
        latitude: float,
        longitude: float,
        allowed_radius_meters: int,
        timezone_iana: str,
        address_line1: str | None,
        city: str | None,
        state_region: str | None,
        country_code: str | None,
        postal_code: str | None,
        status: str,
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.tenant_locations
                (location_id,tenant_id,location_code,location_name,location_type,
                 latitude,longitude,allowed_radius_meters,timezone_iana,address_line1,
                 city,state_region,country_code,postal_code,status,created_at_utc,updated_at_utc)
                VALUES
                (:location_id,:tenant_id,:location_code,:location_name,:location_type,
                 :latitude,:longitude,:allowed_radius_meters,:timezone_iana,:address_line1,
                 :city,:state_region,:country_code,:postal_code,:status,:now,:now)
                ON CONFLICT (location_id) DO UPDATE SET
                  location_code=EXCLUDED.location_code,
                  location_name=EXCLUDED.location_name,
                  location_type=EXCLUDED.location_type,
                  latitude=EXCLUDED.latitude,
                  longitude=EXCLUDED.longitude,
                  allowed_radius_meters=EXCLUDED.allowed_radius_meters,
                  timezone_iana=EXCLUDED.timezone_iana,
                  address_line1=EXCLUDED.address_line1,
                  city=EXCLUDED.city,
                  state_region=EXCLUDED.state_region,
                  country_code=EXCLUDED.country_code,
                  postal_code=EXCLUDED.postal_code,
                  status=EXCLUDED.status,
                  updated_at_utc=EXCLUDED.updated_at_utc
                WHERE security.tenant_locations.tenant_id=EXCLUDED.tenant_id
                """
            ),
            {
                "location_id": location_id,
                "tenant_id": tenant_id,
                "location_code": location_code,
                "location_name": location_name,
                "location_type": location_type,
                "latitude": latitude,
                "longitude": longitude,
                "allowed_radius_meters": allowed_radius_meters,
                "timezone_iana": timezone_iana,
                "address_line1": address_line1,
                "city": city,
                "state_region": state_region,
                "country_code": country_code,
                "postal_code": postal_code,
                "status": status,
                "now": now,
            },
        )

    def location(self, *, tenant_id: str, location_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT * FROM security.tenant_locations
                WHERE tenant_id=:tenant_id AND location_id=:location_id
                """
            ),
            {"tenant_id": tenant_id, "location_id": location_id},
        ).mappings().first()
        return dict(row) if row else None

    def commit(self) -> None:
        self.s.commit()

    def rollback(self) -> None:
        self.s.rollback()
