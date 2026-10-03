from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.schemas import (
    AttendanceActionRequest,
    AttendancePolicyResponse,
    AttendanceWorkContext,
    LocationEvidence,
    OutletContext,
)
from verigence_security.attendance.service import AttendanceRuleError, AttendanceService

TENANT_ID = UUID("00000000-0000-4000-8000-000000000201")
USER_ID = UUID("00000000-0000-4000-8000-000000000101")
DEALER_ID = UUID("00000000-0000-4000-8000-000000000301")
OUTLET_ID = UUID("00000000-0000-4000-8000-000000000401")


def _service() -> AttendanceService:
    return AttendanceService(
        repository=object(),  # type: ignore[arg-type]
        settings=AttendanceSettings(),
        security=object(),  # type: ignore[arg-type]
        audit_core=object(),  # type: ignore[arg-type]
    )


def _policy() -> AttendancePolicyResponse:
    return AttendancePolicyResponse(
        tenantId=TENANT_ID,
        timezoneIana="Asia/Kolkata",
        expectedStartLocal="09:00:00",
        checkinReminderLocal="08:45:00",
        expectedEndLocal="18:00:00",
        checkoutReminderLocal="17:45:00",
        pcGeofenceRadiusMeters=300,
        maxLocationAccuracyMeters=150,
        maxLocationAgeSeconds=120,
        geofenceExceptionAllowed=True,
    )


def _request(*, latitude: float, longitude: float, reason: str | None = None) -> AttendanceActionRequest:
    return AttendanceActionRequest(
        location=LocationEvidence(
            latitude=latitude,
            longitude=longitude,
            accuracyMeters=20,
            capturedAt=datetime.now(UTC),
        ),
        exceptionReason=reason,
    )


def _pc_context() -> AttendanceWorkContext:
    return AttendanceWorkContext(
        userId=USER_ID,
        operatingRole="PC",
        geofenceRequired=True,
        outlets=[
            OutletContext(
                dealerId=DEALER_ID,
                outletId=OUTLET_ID,
                outletName="Assigned Outlet",
                latitude=20.2961,
                longitude=85.8245,
            )
        ],
    )


def test_pc_inside_geofence_is_accepted() -> None:
    decision = _service()._geofence(
        request=_request(latitude=20.2962, longitude=85.8246),
        context=_pc_context(),
        policy=_policy(),
    )

    assert decision.required is True
    assert decision.exception is False
    assert decision.result_code == "WITHIN_GEOFENCE"
    assert decision.matched_outlet is not None
    assert decision.matched_outlet.outletId == OUTLET_ID
    assert decision.distance_m is not None and decision.distance_m < 300


def test_pc_outside_geofence_requires_reason() -> None:
    with pytest.raises(AttendanceRuleError) as exc_info:
        _service()._geofence(
            request=_request(latitude=20.40, longitude=85.90),
            context=_pc_context(),
            policy=_policy(),
        )

    assert exc_info.value.code == "GEOFENCE_EXCEPTION_REASON_REQUIRED"


def test_pc_outside_geofence_with_reason_is_exception_not_normal_checkin() -> None:
    decision = _service()._geofence(
        request=_request(
            latitude=20.40,
            longitude=85.90,
            reason="Customer visit instructed by manager",
        ),
        context=_pc_context(),
        policy=_policy(),
    )

    assert decision.required is True
    assert decision.exception is True
    assert decision.result_code == "OUTSIDE_GEOFENCE_EXCEPTION"
    assert decision.distance_m is not None and decision.distance_m > 300


def test_tl_location_is_captured_without_geofence() -> None:
    context = AttendanceWorkContext(
        userId=USER_ID,
        operatingRole="TL",
        geofenceRequired=False,
        outlets=[],
    )
    decision = _service()._geofence(
        request=_request(latitude=20.2962, longitude=85.8246),
        context=context,
        policy=_policy(),
    )

    assert decision.required is False
    assert decision.exception is False
    assert decision.result_code == "LOCATION_CAPTURED"


def test_stale_location_is_rejected() -> None:
    request = AttendanceActionRequest(
        location=LocationEvidence(
            latitude=20.2962,
            longitude=85.8246,
            accuracyMeters=20,
            capturedAt=datetime.now(UTC) - timedelta(minutes=10),
        )
    )

    with pytest.raises(AttendanceRuleError) as exc_info:
        _service()._validate_location(request, _policy(), datetime.now(UTC))

    assert exc_info.value.code == "LOCATION_NOT_FRESH"


def test_inaccurate_location_is_rejected() -> None:
    request = AttendanceActionRequest(
        location=LocationEvidence(
            latitude=20.2962,
            longitude=85.8246,
            accuracyMeters=500,
            capturedAt=datetime.now(UTC),
        )
    )

    with pytest.raises(AttendanceRuleError) as exc_info:
        _service()._validate_location(request, _policy(), datetime.now(UTC))

    assert exc_info.value.code == "LOCATION_ACCURACY_INSUFFICIENT"
