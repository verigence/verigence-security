from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.runtime_service import RuntimeAttendanceService
from verigence_security.attendance.schemas import (
    AttendanceActionRequest,
    AttendancePolicyResponse,
    AttendanceWorkContext,
    LocationEvidence,
    OutletContext,
)
from verigence_security.attendance.service import AttendanceRuleError

TENANT_ID = UUID("00000000-0000-4000-8000-000000000201")
USER_ID = UUID("00000000-0000-4000-8000-000000000101")
DEALER_ID = UUID("00000000-0000-4000-8000-000000000301")
OUTLET_ID = UUID("00000000-0000-4000-8000-000000000401")


def _service() -> RuntimeAttendanceService:
    return RuntimeAttendanceService(
        repository=object(),  # type: ignore[arg-type]
        settings=AttendanceSettings(),
        security=object(),  # type: ignore[arg-type]
        audit_core=object(),  # type: ignore[arg-type]
    )


def _policy(*, exception_allowed: bool = False) -> AttendancePolicyResponse:
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
        geofenceExceptionAllowed=exception_allowed,
    )


def _request(*, reason: str | None = None) -> AttendanceActionRequest:
    return AttendanceActionRequest(
        location=LocationEvidence(
            latitude=20.40,
            longitude=85.90,
            accuracyMeters=20,
            capturedAt=datetime.now(UTC),
        ),
        exceptionReason=reason,
    )


def _context(*, with_coordinates: bool = True) -> AttendanceWorkContext:
    return AttendanceWorkContext(
        userId=USER_ID,
        operatingRole="PC",
        geofenceRequired=True,
        outlets=[
            OutletContext(
                dealerId=DEALER_ID,
                outletId=OUTLET_ID,
                outletName="Assigned Outlet",
                latitude=20.2961 if with_coordinates else None,
                longitude=85.8245 if with_coordinates else None,
            )
        ],
    )


def test_offsite_pc_requires_employee_business_remark() -> None:
    with pytest.raises(AttendanceRuleError) as exc_info:
        _service()._geofence(
            request=_request(),
            context=_context(),
            policy=_policy(),
        )

    assert exc_info.value.code == "GEOFENCE_EXCEPTION_REASON_REQUIRED"


def test_offsite_pc_is_recorded_as_exception_even_if_policy_previously_blocked() -> None:
    decision = _service()._geofence(
        request=_request(reason="Working from home due to customer calls"),
        context=_context(),
        policy=_policy(exception_allowed=False),
    )

    assert decision.required is True
    assert decision.exception is True
    assert decision.result_code == "OUTSIDE_GEOFENCE_EXCEPTION"
    assert decision.distance_m is not None and decision.distance_m > 300


def test_missing_outlet_coordinates_becomes_review_exception_with_employee_remark() -> None:
    decision = _service()._geofence(
        request=_request(reason="Working from home today"),
        context=_context(with_coordinates=False),
        policy=_policy(),
    )

    assert decision.required is True
    assert decision.exception is True
    assert decision.result_code == "GEOFENCE_UNVERIFIABLE_EXCEPTION"
    assert decision.matched_outlet is None
    assert decision.distance_m is None
