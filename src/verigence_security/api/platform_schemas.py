from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr, model_validator


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
    newPassword: SecretStr


class PlatformMeResponse(BaseModel):
    userId: UUID
    roles: list[str]
    permissions: list[str]
    mustChangePassword: bool


class PlatformTenantCreateRequest(BaseModel):
    tenantCode: str = Field(min_length=1, max_length=80)
    tenantName: str = Field(min_length=1, max_length=240)

    @model_validator(mode="after")
    def normalize_required_values(self) -> PlatformTenantCreateRequest:
        self.tenantCode = self.tenantCode.strip()
        self.tenantName = self.tenantName.strip()
        if not self.tenantCode or not self.tenantName:
            raise ValueError("Tenant code and name cannot be blank")
        return self


class PlatformTenantUpdateRequest(BaseModel):
    tenantName: str = Field(min_length=1, max_length=240)

    @model_validator(mode="after")
    def normalize_name(self) -> PlatformTenantUpdateRequest:
        self.tenantName = self.tenantName.strip()
        if not self.tenantName:
            raise ValueError("Tenant name cannot be blank")
        return self


class PlatformTenantResponse(BaseModel):
    tenantId: UUID
    tenantCode: str
    tenantName: str
    status: str
    createdAtUtc: datetime
    updatedAtUtc: datetime
