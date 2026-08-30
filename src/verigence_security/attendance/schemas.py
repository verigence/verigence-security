from __future__ import annotations

from datetime import date, datetime, time
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class HumanContext(BaseModel):
    user_id: UUID
    bearer_token: str


class LocationEvidence(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    accuracyMeters: float = Field(ge=0, le=10000)
    capturedAt: datetime


class LocationResolutionRequest(BaseModel):
    location: LocationEvidence


class LocationResolutionResponse(BaseModel):
    displayAddress: str
    provider: str
    attribution: str


class AttendanceActionRequest(BaseModel):
    location: LocationEvidence
    exceptionReason: str | None = Field(default=None, max_length=500)
    displayAddress: str | None = Field(default=None, max_length=1000)
    locationConfirmed: bool | None = None
    locationRemarks: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def require_remarks_when_location_not_confirmed(self) -> AttendanceActionRequest:
        if self.locationConfirmed is False and len((self.locationRemarks or "").strip()) < 3:
            raise ValueError("Location remarks are required when the employee does not confirm the displayed location.")
        return self


class OutletContext(BaseModel):
    dealerId: UUID
    outletId: UUID
    outletName: str
    latitude: float | None = None
    longitude: float | None = None


class AttendanceWorkContext(BaseModel):
    userId: UUID
    operatingRole: str
    geofenceRequired: bool
    outlets: list[OutletContext] = Field(default_factory=list)


class AttendancePolicyResponse(BaseModel):
    tenantId: UUID
    timezoneIana: str
    expectedStartLocal: time
    checkinReminderLocal: time
    expectedEndLocal: time
    checkoutReminderLocal: time
    pcGeofenceRadiusMeters: int
    maxLocationAccuracyMeters: float
    maxLocationAgeSeconds: int
    geofenceExceptionAllowed: bool


class AttendancePolicyUpdate(BaseModel):
    timezoneIana: str = Field(min_length=1, max_length=80)
    expectedStartLocal: time
    checkinReminderLocal: time
    expectedEndLocal: time
    checkoutReminderLocal: time
    pcGeofenceRadiusMeters: int = Field(ge=50, le=5000)
    maxLocationAccuracyMeters: float = Field(gt=0, le=5000)
    maxLocationAgeSeconds: int = Field(ge=10, le=900)
    geofenceExceptionAllowed: bool = True


class AttendanceRecord(BaseModel):
    attendanceId: UUID
    tenantId: UUID
    userId: UUID
    attendanceDate: date
    roleKey: str
    status: str
    checkInAt: datetime
    checkInResult: str
    checkInOutletId: UUID | None = None
    checkInDealerId: UUID | None = None
    checkInDistanceMeters: float | None = None
    checkOutAt: datetime | None = None
    checkOutResult: str | None = None
    checkOutOutletId: UUID | None = None
    checkOutDealerId: UUID | None = None
    checkOutDistanceMeters: float | None = None


class AttendanceActionResponse(BaseModel):
    attendance: AttendanceRecord
    geofenceRequired: bool
    matchedOutlet: OutletContext | None = None
    distanceMeters: float | None = None
    exceptionRecorded: bool = False


class TodayResponse(BaseModel):
    attendance: AttendanceRecord | None = None
    policy: AttendancePolicyResponse
    reminder: Literal["CHECK_IN", "CHECK_OUT"] | None = None


class AttendanceListResponse(BaseModel):
    items: list[AttendanceRecord]


class AttendanceRosterMember(BaseModel):
    userId: UUID
    displayName: str
    primaryEmail: str | None = None
    operatingRole: str | None = None


class AttendanceLocationConfirmationSummary(BaseModel):
    displayAddress: str
    employeeConfirmed: bool
    remarks: str | None = None


class AttendanceOverviewItem(BaseModel):
    userId: UUID
    displayName: str
    primaryEmail: str | None = None
    roleKey: str | None = None
    status: str
    attendance: AttendanceRecord | None = None
    checkInLocationConfirmation: AttendanceLocationConfirmationSummary | None = None
    checkOutLocationConfirmation: AttendanceLocationConfirmationSummary | None = None


class AttendanceOverviewResponse(BaseModel):
    attendanceDate: date
    totalEmployees: int
    checkedIn: int
    checkedOut: int
    notCheckedIn: int
    exceptions: int
    items: list[AttendanceOverviewItem]


class CapabilityResponse(BaseModel):
    canSelfRead: bool
    canCheckIn: bool
    canCheckOut: bool
    canTeamRead: bool
    canAllRead: bool
    canCorrect: bool
    canManagePolicy: bool
    canReadReports: bool
    roleKey: str | None = None


class CorrectionRequest(BaseModel):
    checkInAt: datetime | None = None
    checkOutAt: datetime | None = None
    reason: str = Field(min_length=3, max_length=1000)
