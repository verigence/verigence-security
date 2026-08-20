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
    """Legacy Tenant/device/Geo login-session shape retained for compatibility code/tests."""

    identifier: str = Field(min_length=1, max_length=320)
    password: SecretStr
    totpCode: SecretStr | None = None


class HumanLoginRequest(BaseModel):
    """Canonical Phase-1 global human login request."""

    identifier: str = Field(min_length=1, max_length=320)
    password: SecretStr


class HumanLoginResponse(BaseModel):
    accessToken: str
    expiresAtUtc: datetime
    actorType: ActorType
    # UI navigation hint only. Authorization remains Security-side and is never trusted from Web.
    isSuperAdmin: bool = False


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
