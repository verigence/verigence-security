from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from verigence_security.attendance.schemas import (
    AttendanceActionRequest,
    AttendanceActionResponse,
    AttendanceWorkContext,
)
from verigence_security.attendance.service import AttendanceRuleError, AttendanceService


class RuntimeAttendanceService(AttendanceService):
    """Phase-1 action service with the narrowest possible Audit Core dependency.

    TL/PM/CRM/Executive operating users do not call Audit Core during attendance
    actions because their Phase-1 rule is location capture only. PC resolves Outlet
    coordinates because geofencing is mandatory. A secondary HRADMIN assignment may
    mask an underlying operating role in the Security decision, so that case performs
    the optional Audit Core lookup to preserve PC geofencing when roles coexist.
    """

    def _work_context_for_action(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        human_bearer_token: str,
        authorization: dict[str, object],
    ) -> AttendanceWorkContext:
        role_key = str(authorization.get("roleKey") or "").strip()
        classification = str(authorization.get("classification") or "").strip()

        if classification == "Operating" and role_key and role_key != "PC":
            return AttendanceWorkContext(
                userId=user_id,
                operatingRole=role_key,
                geofenceRequired=False,
                outlets=[],
            )

        context = self.audit_core.current_work_context(
            tenant_id=tenant_id,
            human_bearer_token=human_bearer_token,
        )
        if context is None:
            if role_key == "PC":
                raise AttendanceRuleError(
                    "PC_GEOFENCE_CONTEXT_UNAVAILABLE",
                    "Your active PC Outlet assignment could not be resolved for attendance.",
                )
            return AttendanceWorkContext(
                userId=user_id,
                operatingRole=role_key or classification or "ATTENDANCE_USER",
                geofenceRequired=False,
                outlets=[],
            )
        if context.userId != user_id:
            raise AttendanceRuleError(
                "WORK_CONTEXT_MISMATCH",
                "Attendance work context does not match the authenticated user.",
            )
        if context.operatingRole == "PC" and not context.geofenceRequired:
            raise AttendanceRuleError(
                "PC_GEOFENCE_CONTEXT_INVALID",
                "PC attendance requires geofence validation.",
            )
        return context

    def check_in(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        human_bearer_token: str,
        request: AttendanceActionRequest,
    ) -> AttendanceActionResponse:
        authorization = self._authorize(
            user_id=user_id,
            tenant_id=tenant_id,
            permission="attendance.self.checkin",
        )
        policy = self._policy(tenant_id)
        now_utc = datetime.now(UTC)
        self._validate_location(request, policy, now_utc)
        attendance_date = self._business_date(policy, now_utc)
        if self.repository.for_date(
            tenant_id=tenant_id,
            user_id=user_id,
            attendance_date=attendance_date,
        ) is not None:
            raise AttendanceRuleError(
                "ALREADY_CHECKED_IN",
                "Attendance has already been started today.",
            )

        context = self._work_context_for_action(
            tenant_id=tenant_id,
            user_id=user_id,
            human_bearer_token=human_bearer_token,
            authorization=authorization,
        )
        decision = self._geofence(request=request, context=context, policy=policy)
        reason = (request.exceptionReason or "").strip() or None
        row = self.repository.create_check_in(
            {
                "tenant_id": tenant_id,
                "user_id": user_id,
                "attendance_date": attendance_date,
                "role_key": context.operatingRole,
                "status": "CHECKED_IN_EXCEPTION" if decision.exception else "CHECKED_IN",
                "check_in_at_utc": now_utc,
                "latitude": request.location.latitude,
                "longitude": request.location.longitude,
                "accuracy_m": request.location.accuracyMeters,
                "dealer_id": decision.matched_outlet.dealerId if decision.matched_outlet else None,
                "outlet_id": decision.matched_outlet.outletId if decision.matched_outlet else None,
                "distance_m": decision.distance_m,
                "result_code": decision.result_code,
                "exception_reason": reason if decision.exception else None,
            }
        )
        attendance_id = UUID(str(row["attendance_id"]))
        self.repository.append_event(
            attendance_id=attendance_id,
            tenant_id=tenant_id,
            user_id=user_id,
            event_type="GEOFENCE_EXCEPTION" if decision.exception else "CHECK_IN",
            latitude=request.location.latitude,
            longitude=request.location.longitude,
            accuracy_m=request.location.accuracyMeters,
            dealer_id=decision.matched_outlet.dealerId if decision.matched_outlet else None,
            outlet_id=decision.matched_outlet.outletId if decision.matched_outlet else None,
            distance_m=decision.distance_m,
            result_code=decision.result_code,
            reason=reason if decision.exception else None,
            metadata={"capturedAt": request.location.capturedAt.isoformat()},
        )
        return AttendanceActionResponse(
            attendance=self._record(row),
            geofenceRequired=decision.required,
            matchedOutlet=decision.matched_outlet,
            distanceMeters=decision.distance_m,
            exceptionRecorded=decision.exception,
        )

    def check_out(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        human_bearer_token: str,
        request: AttendanceActionRequest,
    ) -> AttendanceActionResponse:
        authorization = self._authorize(
            user_id=user_id,
            tenant_id=tenant_id,
            permission="attendance.self.checkout",
        )
        policy = self._policy(tenant_id)
        now_utc = datetime.now(UTC)
        self._validate_location(request, policy, now_utc)
        row = self.repository.for_date(
            tenant_id=tenant_id,
            user_id=user_id,
            attendance_date=self._business_date(policy, now_utc),
        )
        if row is None:
            raise AttendanceRuleError("NOT_CHECKED_IN", "No check-in exists for today.")
        if row.get("check_out_at_utc") is not None:
            raise AttendanceRuleError(
                "ALREADY_CHECKED_OUT",
                "Attendance has already been completed today.",
            )

        context = self._work_context_for_action(
            tenant_id=tenant_id,
            user_id=user_id,
            human_bearer_token=human_bearer_token,
            authorization=authorization,
        )
        decision = self._geofence(request=request, context=context, policy=policy)
        reason = (request.exceptionReason or "").strip() or None
        attendance_id = UUID(str(row["attendance_id"]))
        updated = self.repository.check_out(
            {
                "tenant_id": tenant_id,
                "attendance_id": attendance_id,
                "status": "CHECKED_OUT_EXCEPTION" if decision.exception else "CHECKED_OUT",
                "check_out_at_utc": now_utc,
                "latitude": request.location.latitude,
                "longitude": request.location.longitude,
                "accuracy_m": request.location.accuracyMeters,
                "dealer_id": decision.matched_outlet.dealerId if decision.matched_outlet else None,
                "outlet_id": decision.matched_outlet.outletId if decision.matched_outlet else None,
                "distance_m": decision.distance_m,
                "result_code": decision.result_code,
                "exception_reason": reason if decision.exception else None,
            }
        )
        if updated is None:
            raise AttendanceRuleError(
                "ALREADY_CHECKED_OUT",
                "Attendance has already been completed today.",
            )
        self.repository.append_event(
            attendance_id=attendance_id,
            tenant_id=tenant_id,
            user_id=user_id,
            event_type="GEOFENCE_EXCEPTION" if decision.exception else "CHECK_OUT",
            latitude=request.location.latitude,
            longitude=request.location.longitude,
            accuracy_m=request.location.accuracyMeters,
            dealer_id=decision.matched_outlet.dealerId if decision.matched_outlet else None,
            outlet_id=decision.matched_outlet.outletId if decision.matched_outlet else None,
            distance_m=decision.distance_m,
            result_code=decision.result_code,
            reason=reason if decision.exception else None,
            metadata={"capturedAt": request.location.capturedAt.isoformat()},
        )
        return AttendanceActionResponse(
            attendance=self._record(updated),
            geofenceRequired=decision.required,
            matchedOutlet=decision.matched_outlet,
            distanceMeters=decision.distance_m,
            exceptionRecorded=decision.exception,
        )
