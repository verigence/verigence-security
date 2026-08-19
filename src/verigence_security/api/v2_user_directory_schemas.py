from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class GlobalUserDirectoryResponse(BaseModel):
    userId: str
    displayName: str
    primaryEmail: str | None
    primaryMobile: str | None
    status: str
    clerkSubject: str | None
    onboardingStatus: str | None
    createdAtUtc: datetime
    updatedAtUtc: datetime
