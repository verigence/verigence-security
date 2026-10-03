from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from verigence_security.attendance.schemas import AttendanceActionRequest, LocationEvidence


def location() -> LocationEvidence:
    return LocationEvidence(
        latitude=30.7046,
        longitude=76.7179,
        accuracyMeters=20,
        capturedAt=datetime.now(UTC),
    )


def test_location_confirmation_yes_does_not_require_remarks() -> None:
    request = AttendanceActionRequest(
        location=location(),
        displayAddress="Sector 66, Mohali, Punjab, India",
        locationConfirmed=True,
    )
    assert request.locationConfirmed is True
    assert request.locationRemarks is None


def test_location_confirmation_no_requires_remarks() -> None:
    with pytest.raises(ValidationError):
        AttendanceActionRequest(
            location=location(),
            displayAddress="Sector 66, Mohali, Punjab, India",
            locationConfirmed=False,
        )


def test_location_confirmation_no_accepts_employee_remarks() -> None:
    request = AttendanceActionRequest(
        location=location(),
        displayAddress="Sector 66, Mohali, Punjab, India",
        locationConfirmed=False,
        locationRemarks="GPS pin is showing the adjacent building.",
    )
    assert request.locationConfirmed is False
    assert request.locationRemarks == "GPS pin is showing the adjacent building."


def test_legacy_action_contract_remains_valid_during_rollout() -> None:
    request = AttendanceActionRequest(location=location())
    assert request.locationConfirmed is None
    assert request.displayAddress is None
