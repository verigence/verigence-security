from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr

from verigence_security.core.types import ActorType, GeoIntegrityStatus, GeoSource


class GeoContext(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    accuracyMeters: float = Field(ge=0)
    capturedAt: datetime
    source: GeoSource
    integrityStatus: GeoIntegrityStatus
    integrityReason: str | None = Field(default=None, max_length=240)


class AccessSessionRequest(BaseModel):
    tenantId: UUID
    deviceId: UUID
    geo: GeoContext


class CredentialAccessSessionRequest(AccessSessionRequest):
    """Legacy Tenant/device/Geo login-session shape retained for compatibility code/tests."""

    identifier: str = Field(min_length=1, max_length=320)
    password: SecretStr
    totpCode: SecretStr | None = None


class HumanDeviceContext(BaseModel):
    """Cheap, locally available device/browser context carried on human login."""

    deviceId: UUID
    deviceType: Literal["MOBILE", "WEB"]
    platform: Literal["ANDROID", "IOS", "WINDOWS", "MACOS", "LINUX", "OTHER"]
    deviceName: str | None = Field(default=None, max_length=240)
    deviceModel: str | None = Field(default=None, max_length=160)
    osVersion: str | None = Field(default=None, max_length=120)
    browserName: str | None = Field(default=None, max_length=120)
    browserVersion: str | None = Field(default=None, max_length=120)
    appVersion: str | None = Field(default=None, max_length=120)


class HumanLoginRequest(BaseModel):
    """Canonical global human login request.

    `device` is optional for compatibility with older clients during rollout. Current Web/Mobile
    supplies it so Security can bind the issued human token to a stable installation UUID without
    introducing another pre-login network request.
    """

    identifier: str = Field(min_length=1, max_length=320)
    password: SecretStr
    device: HumanDeviceContext | None = None


class HumanLoginResponse(BaseModel):
    accessToken: str
    expiresAtUtc: datetime
    actorType: ActorType
    # UI navigation hint only. Authorization remains Security-side and is never trusted from Web.
    isSuperAdmin: bool = False
    sessionId: UUID
    deviceId: UUID


class HumanGeoObservation(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    accuracyMeters: float | None = Field(default=None, ge=0)
    capturedAt: datetime
    source: Literal["BROWSER", "NATIVE"]


class HumanSessionObservationRequest(BaseModel):
    deviceType: Literal["MOBILE", "WEB"]
    platform: Literal["ANDROID", "IOS", "WINDOWS", "MACOS", "LINUX", "OTHER"]
    deviceName: str | None = Field(default=None, max_length=240)
    deviceModel: str | None = Field(default=None, max_length=160)
    osVersion: str | None = Field(default=None, max_length=120)
    browserName: str | None = Field(default=None, max_length=120)
    browserVersion: str | None = Field(default=None, max_length=120)
    appVersion: str | None = Field(default=None, max_length=120)
    geoStatus: Literal["PENDING", "AVAILABLE", "DENIED", "UNAVAILABLE", "TIMEOUT"] = "PENDING"
    geo: HumanGeoObservation | None = None


class HumanSessionObservationResponse(BaseModel):
    observationMode: Literal["OBSERVE"] = "OBSERVE"
    previousSessionSuperseded: bool
    previousSessionDifferentDevice: bool
    activeDeviceCount: int = Field(ge=0)
    deviceLimit: int = Field(gt=0)
    deviceLimitExceeded: bool
    geoRecorded: bool


class RefreshAccessSessionRequest(BaseModel):
    geo: GeoContext


class AccessTokenResponse(BaseModel):
    accessSessionId: UUID
    accessToken: str
    expiresAtUtc: datetime
    actorType: ActorType
    tenantId: UUID
    deviceId: UUID | None = None
    locationId: UUID | None = None
    roles: list[str] = Field(default_factory=list)
    permissions: list[str]


class DevMockTokenRequest(BaseModel):
    userId: UUID
