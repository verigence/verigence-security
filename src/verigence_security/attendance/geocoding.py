from __future__ import annotations

from typing import Any

import httpx

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.schemas import LocationEvidence, LocationResolutionResponse
from verigence_security.attendance.security import AttendanceDependencyError


class AttendanceReverseGeocoder:
    """Translate GPS evidence into a human-readable display address.

    GPS coordinates remain the authoritative attendance evidence. The returned address
    exists only so the employee can understand and confirm what location was captured.
    The provider URL is configurable so production can move to a dedicated geocoder
    without changing the Attendance contract.
    """

    def __init__(self, settings: AttendanceSettings) -> None:
        self.settings = settings

    def resolve(self, location: LocationEvidence) -> LocationResolutionResponse:
        base_url = self.settings.reverse_geocode_base_url.strip().rstrip("/")
        if not base_url:
            raise AttendanceDependencyError("Attendance reverse geocoding is not configured")

        try:
            response = httpx.get(
                f"{base_url}/reverse",
                params={
                    "format": "jsonv2",
                    "lat": location.latitude,
                    "lon": location.longitude,
                    "zoom": 18,
                    "addressdetails": 1,
                },
                headers={
                    "User-Agent": self.settings.reverse_geocode_user_agent,
                    "Accept-Language": "en",
                },
                timeout=self.settings.reverse_geocode_timeout_seconds,
            )
            response.raise_for_status()
            payload: Any = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise AttendanceDependencyError("Unable to translate the captured location into an address") from exc

        display_address = ""
        if isinstance(payload, dict):
            display_address = str(payload.get("display_name") or "").strip()
        if not display_address:
            raise AttendanceDependencyError("No readable address was found for the captured location")

        return LocationResolutionResponse(
            displayAddress=display_address,
            provider="OpenStreetMap Nominatim",
            attribution="Address data © OpenStreetMap contributors",
        )
