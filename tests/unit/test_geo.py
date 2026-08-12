from datetime import UTC, datetime, timedelta

import pytest

from verigence_security.core.errors import SecurityError
from verigence_security.core.types import GeoIntegrityStatus, GeoSource
from verigence_security.services.geo import (
    GeoSample,
    LocationCandidate,
    haversine_meters,
    match_location,
    validate_geo,
)


def sample(**kwargs):
    base = dict(
        latitude=28.4595,
        longitude=77.0266,
        accuracy_meters=8,
        captured_at=datetime.now(UTC),
        source=GeoSource.NATIVE,
        integrity_status=GeoIntegrityStatus.NORMAL,
    )
    base.update(kwargs)
    return GeoSample(**base)


def test_haversine_zero():
    assert haversine_meters(1, 2, 1, 2) == 0


def test_match_nearest_location():
    s = sample()
    a = LocationCandidate("a", 28.4595, 77.0266, 100, "Asia/Kolkata", "sched-a")
    b = LocationCandidate("b", 28.4596, 77.0267, 100, "Asia/Kolkata", "sched-b")
    loc, distance = match_location(s, [b, a])
    assert loc.location_id == "a"
    assert distance == 0


def test_spoof_signal_denied():
    with pytest.raises(SecurityError) as exc:
        validate_geo(
            sample(integrity_status=GeoIntegrityStatus.SUSPECTED),
            max_accuracy_meters=50,
            max_age_seconds=60,
        )
    assert exc.value.code == "GEO_INTEGRITY_FAILED"


def test_future_geo_is_rejected_without_hidden_clock_skew_default():
    now = datetime.now(UTC)
    with pytest.raises(SecurityError) as exc:
        validate_geo(
            sample(captured_at=now + timedelta(seconds=1)),
            max_accuracy_meters=50,
            max_age_seconds=60,
            now=now,
        )
    assert exc.value.code == "GEO_STALE"
