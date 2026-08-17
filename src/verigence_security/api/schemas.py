from __future__ import annotations

from datetime import datetime
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
    identifier: str = Field(min_length=1, max_length=320)
    password: SecretStr
    totpCode: SecretStr | None = None


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
