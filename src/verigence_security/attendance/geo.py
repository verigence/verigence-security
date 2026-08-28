from __future__ import annotations

from math import asin, cos, radians, sin, sqrt

EARTH_RADIUS_M = 6_371_000.0


def distance_meters(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance using the Haversine formula."""
    phi1 = radians(lat1)
    phi2 = radians(lat2)
    dphi = radians(lat2 - lat1)
    dlambda = radians(lon2 - lon1)
    a = sin(dphi / 2) ** 2 + cos(phi1) * cos(phi2) * sin(dlambda / 2) ** 2
    return 2 * EARTH_RADIUS_M * asin(sqrt(a))
