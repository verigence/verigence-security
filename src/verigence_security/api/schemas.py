from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

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


class PlatformAdminBootstrapRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120, pattern=r"^[a-zA-Z0-9._-]+$")
    displayName: str = Field(min_length=1, max_length=240)
    password: str = Field(min_length=8, max_length=128)


class PlatformAdminBootstrapResponse(BaseModel):
    adminId: UUID
    username: str
    displayName: str
    role: str = "SUPER_ADMIN"
    mustChangePassword: bool


class PlatformAdminLoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120)
    password: str = Field(min_length=1, max_length=128)


class PlatformAdminTokenResponse(BaseModel):
    accessToken: str
    tokenType: str = "Bearer"
    expiresAtUtc: datetime
    adminId: UUID
    username: str
    role: str
    mustChangePassword: bool


class TenantCreateRequest(BaseModel):
    tenantCode: str = Field(
        min_length=2,
        max_length=80,
        pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$",
    )
    tenantName: str = Field(min_length=1, max_length=240)


class TenantAdminResponse(BaseModel):
    tenantId: UUID
    tenantCode: str
    tenantName: str
    status: str
    createdAtUtc: datetime | None = None
    updatedAtUtc: datetime | None = None
