from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from uuid import UUID

from verigence_security.attendance.audit_core import AuditCoreAttendanceClient
from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.geo import distance_meters
from verigence_security.attendance.repository import AttendanceRepository
from verigence_security.attendance.schemas import (
    AttendanceActionRequest,
    AttendanceActionResponse,
    AttendanceListResponse,
    AttendancePolicyResponse,
    AttendancePolicyUpdate,
    AttendanceRecord,
    AttendanceWorkContext,
    CorrectionRequest,
    OutletContext,
    TodayResponse,
)
from verigence_security.attendance.security import SecurityAuthorizationClient


class AttendanceRuleError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class GeofenceDecision:
    required: bool
    result_code: str
    matched_outlet: OutletContext | None = None
    distance_m: float | None = None
    exception: bool = False


class AttendanceService:
    def __init__(
        self,
        *,
        repository: AttendanceRepository,
        settings: AttendanceSettings,
        security: SecurityAuthorizationClient,
        audit_core: AuditCoreAttendanceClient,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.security = security
        self.audit_core = audit_core

    def _authorize(self, *, user_id: UUID, tenant_id: UUID, permission: str) -> dict[str, object]:
        return self.security.check(
            user_id=user_id,
            tenant_id=tenant_id,
            permission_key=permission,
        )

    def _policy(self, tenant_id: UUID) -> AttendancePolicyResponse:
        row = self.repository.policy(tenant_id)
        if row is None:
            return AttendancePolicyResponse(
                tenantId=tenant_id,
                timezoneIana=self.settings.default_timezone,
                expectedStartLocal=time(9, 0),
                checkinReminderLocal=time(8, 45),
                expectedEndLocal=time(18, 0),
                checkoutReminderLocal=time(17, 45),
                pcGeofenceRadiusMeters=self.settings.default_pc_geofence_radius_m,
                maxLocationAccuracyMeters=self.settings.default_max_location_accuracy_m,
                maxLocationAgeSeconds=self.settings.default_max_location_age_seconds,
                geofenceExceptionAllowed=True,
            )
        return AttendancePolicyResponse(
            tenantId=tenant_id,
            timezoneIana=str(row["timezone_iana"]),
            expectedStartLocal=row["expected_start_local"],
            checkinReminderLocal=row["checkin_reminder_local"],
            expectedEndLocal=row["expected_end_local"],
            checkoutReminderLocal=row["checkout_reminder_local"],
            pcGeofenceRadiusMeters=int(row["pc_geofence_radius_m"]),
            maxLocationAccuracyMeters=float(row["max_location_accuracy_m"]),
            maxLocationAgeSeconds=int(row["max_location_age_seconds"]),
            geofenceExceptionAllowed=bool(row["geofence_exception_allowed"]),
        )

    @staticmethod
    def _timezone(policy: AttendancePolicyResponse) -> ZoneInfo:
        try:
            return ZoneInfo(policy.timezoneIana)
        except ZoneInfoNotFoundError as exc:
            raise AttendanceRuleError(
                "ATTENDANCE_POLICY_TIMEZONE_INVALID",
                "Attendance policy timezone is invalid.",
            ) from exc

    def _business_date(self, policy: AttendancePolicyResponse, now_utc: datetime) -> date:
        return now_utc.astimezone(self._timezone(policy)).date()

    @staticmethod
    def _record(row: dict[str, object]) -> AttendanceRecord:
        return AttendanceRecord(
            attendanceId=UUID(str(row["attendance_id"])),
            tenantId=UUID(str(row["tenant_id"])),
            userId=UUID(str(row["user_id"])),
            attendanceDate=row["attendance_date"],
            roleKey=str(row["role_key"]),
            status=str(row["status"]),
            checkInAt=row["check_in_at_utc"],
            checkInResult=str(row["check_in_result"]),
            checkInOutletId=(
                UUID(str(row["check_in_outlet_id"])) if row.get("check_in_outlet_id") else None
            ),
            checkInDealerId=(
                UUID(str(row["check_in_dealer_id"])) if row.get("check_in_dealer_id") else None
            ),
            checkInDistanceMeters=(
                float(row["check_in_distance_m"]) if row.get("check_in_distance_m") is not None else None
            ),
            checkOutAt=row.get("check_out_at_utc"),
            checkOutResult=(str(row["check_out_result"]) if row.get("check_out_result") else None),
            checkOutOutletId=(
                UUID(str(row["check_out_outlet_id"])) if row.get("check_out_outlet_id") else None
            ),
            checkOutDealerId=(
                UUID(str(row["check_out_dealer_id"])) if row.get("check_out_dealer_id") else None
            ),
            checkOutDistanceMeters=(
                float(row["check_out_distance_m"]) if row.get("check_out_distance_m") is not None else None
            ),
        )

    @staticmethod
    def _validate_location(
        request: AttendanceActionRequest,
        policy: AttendancePolicyResponse,
        now_utc: datetime,
    ) -> None:
        location = request.location
        captured_at = location.capturedAt
        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise AttendanceRuleError(
                "LOCATION_TIMESTAMP_REQUIRED",
                "Location evidence must include an offset-aware capture time.",
            )
        age_seconds = (now_utc - captured_at.astimezone(UTC)).total_seconds()
        if age_seconds < -30 or age_seconds > policy.maxLocationAgeSeconds:
            raise AttendanceRuleError(
                "LOCATION_NOT_FRESH",
                "Please capture your location again before recording attendance.",
            )
        if location.accuracyMeters > policy.maxLocationAccuracyMeters:
            raise AttendanceRuleError(
                "LOCATION_ACCURACY_INSUFFICIENT",
                "Location accuracy is not sufficient for attendance. Please retry location capture.",
            )

    @staticmethod
    def _nearest_outlet(
        *,
        request: AttendanceActionRequest,
        context: AttendanceWorkContext,
    ) -> tuple[OutletContext, float] | None:
        candidates: list[tuple[OutletContext, float]] = []
        for outlet in context.outlets:
            if outlet.latitude is None or outlet.longitude is None:
                continue
            distance = distance_meters(
                request.location.latitude,
                request.location.longitude,
                outlet.latitude,
                outlet.longitude,
            )
            candidates.append((outlet, distance))
        return min(candidates, key=lambda item: item[1]) if candidates else None

    def _geofence(
        self,
        *,
        request: AttendanceActionRequest,
        context: AttendanceWorkContext,
        policy: AttendancePolicyResponse,
    ) -> GeofenceDecision:
        if not context.geofenceRequired:
            return GeofenceDecision(required=False, result_code="LOCATION_CAPTURED")

        nearest = self._nearest_outlet(request=request, context=context)
        if nearest is None:
            raise AttendanceRuleError(
                "PC_GEOFENCE_NOT_CONFIGURED",
                "Your assigned Outlet does not have usable geofence coordinates. Contact HR/Admin.",
            )
        outlet, distance = nearest
        if distance <= policy.pcGeofenceRadiusMeters:
            return GeofenceDecision(
                required=True,
                result_code="WITHIN_GEOFENCE",
                matched_outlet=outlet,
                distance_m=distance,
            )

        reason = (request.exceptionReason or "").strip()
        if not policy.geofenceExceptionAllowed:
            raise AttendanceRuleError(
                "OUTSIDE_GEOFENCE",
                "You are outside the assigned Outlet geofence.",
            )
        if not reason:
            raise AttendanceRuleError(
                "GEOFENCE_EXCEPTION_REASON_REQUIRED",
                "You are outside the assigned Outlet geofence. A reason is required to continue.",
            )
        return GeofenceDecision(
            required=True,
            result_code="OUTSIDE_GEOFENCE_EXCEPTION",
            matched_outlet=outlet,
            distance_m=distance,
            exception=True,
        )

    def today(self, *, tenant_id: UUID, user_id: UUID) -> TodayResponse:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.self.read")
        policy = self._policy(tenant_id)
        now_utc = datetime.now(UTC)
        row = self.repository.for_date(
            tenant_id=tenant_id,
            user_id=user_id,
            attendance_date=self._business_date(policy, now_utc),
        )
        reminder: str | None = None
        local_now = now_utc.astimezone(self._timezone(policy)).time().replace(tzinfo=None)
        if row is None and local_now >= policy.checkinReminderLocal:
            reminder = "CHECK_IN"
        elif row is not None and row.get("check_out_at_utc") is None and local_now >= policy.checkoutReminderLocal:
            reminder = "CHECK_OUT"
        return TodayResponse(
            attendance=self._record(row) if row is not None else None,
            policy=policy,
            reminder=reminder,
        )

    def check_in(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        human_bearer_token: str,
        request: AttendanceActionRequest,
    ) -> AttendanceActionResponse:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.self.checkin")
        policy = self._policy(tenant_id)
        now_utc = datetime.now(UTC)
        self._validate_location(request, policy, now_utc)
        attendance_date = self._business_date(policy, now_utc)
        if self.repository.for_date(
            tenant_id=tenant_id,
            user_id=user_id,
            attendance_date=attendance_date,
        ) is not None:
            raise AttendanceRuleError("ALREADY_CHECKED_IN", "Attendance has already been started today.")

        context = self.audit_core.current_work_context(
            tenant_id=tenant_id,
            human_bearer_token=human_bearer_token,
        )
        if context.userId != user_id:
            raise AttendanceRuleError("WORK_CONTEXT_MISMATCH", "Attendance work context does not match the user.")
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
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.self.checkout")
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
            raise AttendanceRuleError("ALREADY_CHECKED_OUT", "Attendance has already been completed today.")

        context = self.audit_core.current_work_context(
            tenant_id=tenant_id,
            human_bearer_token=human_bearer_token,
        )
        if context.userId != user_id:
            raise AttendanceRuleError("WORK_CONTEXT_MISMATCH", "Attendance work context does not match the user.")
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
            raise AttendanceRuleError("ALREADY_CHECKED_OUT", "Attendance has already been completed today.")
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

    def history(self, *, tenant_id: UUID, user_id: UUID, limit: int) -> AttendanceListResponse:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.self.read")
        return AttendanceListResponse(
            items=[
                self._record(row)
                for row in self.repository.history(tenant_id=tenant_id, user_id=user_id, limit=limit)
            ]
        )

    def tenant_day(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        attendance_date: date,
    ) -> AttendanceListResponse:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.all.read")
        rows = self.repository.tenant_day(
            tenant_id=tenant_id,
            attendance_date=attendance_date,
        )
        return AttendanceListResponse(items=[self._record(row) for row in rows])

    def policy(self, *, tenant_id: UUID, user_id: UUID) -> AttendancePolicyResponse:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.policy.read")
        return self._policy(tenant_id)

    def update_policy(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        update: AttendancePolicyUpdate,
    ) -> AttendancePolicyResponse:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.policy.manage")
        try:
            ZoneInfo(update.timezoneIana)
        except ZoneInfoNotFoundError as exc:
            raise AttendanceRuleError("ATTENDANCE_POLICY_TIMEZONE_INVALID", "Unknown timezone.") from exc
        row = self.repository.upsert_policy(
            tenant_id=tenant_id,
            updated_by_user_id=user_id,
            values={
                "timezone_iana": update.timezoneIana,
                "expected_start_local": update.expectedStartLocal,
                "checkin_reminder_local": update.checkinReminderLocal,
                "expected_end_local": update.expectedEndLocal,
                "checkout_reminder_local": update.checkoutReminderLocal,
                "pc_geofence_radius_m": update.pcGeofenceRadiusMeters,
                "max_location_accuracy_m": update.maxLocationAccuracyMeters,
                "max_location_age_seconds": update.maxLocationAgeSeconds,
                "geofence_exception_allowed": update.geofenceExceptionAllowed,
            },
        )
        return AttendancePolicyResponse(
            tenantId=tenant_id,
            timezoneIana=str(row["timezone_iana"]),
            expectedStartLocal=row["expected_start_local"],
            checkinReminderLocal=row["checkin_reminder_local"],
            expectedEndLocal=row["expected_end_local"],
            checkoutReminderLocal=row["checkout_reminder_local"],
            pcGeofenceRadiusMeters=int(row["pc_geofence_radius_m"]),
            maxLocationAccuracyMeters=float(row["max_location_accuracy_m"]),
            maxLocationAgeSeconds=int(row["max_location_age_seconds"]),
            geofenceExceptionAllowed=bool(row["geofence_exception_allowed"]),
        )

    def correct(
        self,
        *,
        tenant_id: UUID,
        user_id: UUID,
        attendance_id: UUID,
        request: CorrectionRequest,
    ) -> AttendanceRecord:
        self._authorize(user_id=user_id, tenant_id=tenant_id, permission="attendance.correction.write")
        row = self.repository.correct(
            tenant_id=tenant_id,
            attendance_id=attendance_id,
            corrected_by_user_id=user_id,
            check_in_at=request.checkInAt,
            check_out_at=request.checkOutAt,
            reason=request.reason.strip(),
        )
        if row is None:
            raise AttendanceRuleError("ATTENDANCE_NOT_FOUND", "Attendance record was not found.")
        self.repository.append_event(
            attendance_id=attendance_id,
            tenant_id=tenant_id,
            user_id=UUID(str(row["user_id"])),
            event_type="CORRECTION",
            latitude=None,
            longitude=None,
            accuracy_m=None,
            dealer_id=None,
            outlet_id=None,
            distance_m=None,
            result_code="CORRECTED",
            reason=request.reason.strip(),
        )
        return self._record(row)
