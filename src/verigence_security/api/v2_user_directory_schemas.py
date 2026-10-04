from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr


class GlobalUserDirectoryResponse(BaseModel):
    userId: str
    displayName: str
    primaryEmail: str | None
    primaryMobile: str | None
    status: str
    clerkSubject: str | None
    onboardingStatus: str | None
    isEmployee: bool = False
    createdAtUtc: datetime
    updatedAtUtc: datetime


class OnboardingKeyAdminRequest(BaseModel):
    onboardingKey: str = Field(min_length=8, max_length=64)
    enabled: bool = True


class PlatformUserCreateRequest(BaseModel):
    firstName: str = Field(min_length=1, max_length=120)
    lastName: str = Field(default="", max_length=120)
    email: str = Field(min_length=3, max_length=320)
    mobile: str = Field(min_length=10, max_length=40)
    password: SecretStr = Field(min_length=1, max_length=256)
