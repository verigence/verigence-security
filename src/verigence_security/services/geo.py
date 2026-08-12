from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from math import asin, cos, radians, sin, sqrt

from verigence_security.core.errors import security_error
from verigence_security.core.types import GeoIntegrityStatus, GeoSource

EARTH_RADIUS_METERS = 6_371_000.0


@dataclass(frozen=True, slots=True)
class GeoSample:
    latitude: float
    longitude: float
    accuracy_meters: float
    captured_at: datetime
    source: GeoSource
    integrity_status: GeoIntegrityStatus
    integrity_reason: str | None = None


@dataclass(frozen=True, slots=True)
class LocationCandidate:
    location_id: str
    latitude: float
    longitude: float
    allowed_radius_meters: float
    timezone_iana: str
    schedule_id: str


def haversine_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = radians(lat1), radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(p1) * cos(p2) * sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_METERS * asin(sqrt(a))


def validate_geo(
    sample: GeoSample,
    *,
    max_accuracy_meters: float,
    max_age_seconds: int,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    captured = (
        sample.captured_at
        if sample.captured_at.tzinfo
        else sample.captured_at.replace(tzinfo=UTC)
    )
    if sample.integrity_status == GeoIntegrityStatus.SUSPECTED:
        raise security_error("GEO_INTEGRITY_FAILED", sample.integrity_reason)
    if sample.accuracy_meters > max_accuracy_meters:
        raise security_error("GEO_ACCURACY_INSUFFICIENT")
    age = (now - captured.astimezone(UTC)).total_seconds()
    # v1.3 does not define a hidden client-clock tolerance. Future-dated geo is therefore rejected
    # rather than introducing an implementation-only skew threshold.
    if age < 0 or age > max_age_seconds:
        raise security_error("GEO_STALE")


def match_location(
    sample: GeoSample,
    candidates: list[LocationCandidate],
) -> tuple[LocationCandidate, float]:
    if not candidates:
        raise security_error("LOCATION_NOT_ASSIGNED")
    matches: list[tuple[float, LocationCandidate]] = []
    for candidate in candidates:
        distance = haversine_meters(
            sample.latitude,
            sample.longitude,
            candidate.latitude,
            candidate.longitude,
        )
        if distance <= candidate.allowed_radius_meters:
            matches.append((distance, candidate))
    if not matches:
        raise security_error("LOCATION_NOT_ALLOWED")
    distance, candidate = min(matches, key=lambda item: item[0])
    return candidate, distance
