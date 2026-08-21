from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr


class PlatformLoginRequest(BaseModel):
    loginName: str = Field(min_length=1, max_length=320)
    password: SecretStr
    totpCode: SecretStr | None = None


class PlatformTokenResponse(BaseModel):
    accessToken: str
    expiresAtUtc: datetime
    userId: UUID
    roles: list[str]
    permissions: list[str]
    mustChangePassword: bool


class PlatformPasswordChangeRequest(BaseModel):
    # Legacy local-password migration debt only. Do not use in the active Clerk backend flow.
    newPassword: str = Field(min_length=1)


class PlatformMeResponse(BaseModel):
    userId: UUID
    roles: list[str]
    permissions: list[str]
    mustChangePassword: bool


class PlatformTenantCreateRequest(BaseModel):
    tenantName: str = Field(min_length=1, max_length=240)

    def model_post_init(self, __context: object) -> None:
        self.tenantName = self.tenantName.strip()
        if not self.tenantName:
            raise ValueError("Tenant name cannot be blank")


class PlatformTenantUpdateRequest(BaseModel):
    tenantName: str = Field(min_length=1, max_length=240)

    def model_post_init(self, __context: object) -> None:
        self.tenantName = self.tenantName.strip()
        if not self.tenantName:
            raise ValueError("Tenant name cannot be blank")


class PlatformTenantResponse(BaseModel):
    tenantId: UUID
    tenantCode: str
    tenantName: str
    status: str
    createdAtUtc: datetime
    updatedAtUtc: datetime
