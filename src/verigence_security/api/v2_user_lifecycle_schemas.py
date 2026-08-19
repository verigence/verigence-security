from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class UserStatusTransitionRequest(BaseModel):
    status: Literal["ACTIVE", "REJECTED", "SUSPENDED", "DISABLED"]
    reasonCode: str | None = Field(default=None, max_length=120)
    reason: str | None = Field(default=None, max_length=1000)


class UserStatusTransitionResponse(BaseModel):
    userId: str
    status: str
    previousStatus: str
    changed: bool
    deletionRequestId: str | None = None


class UserHardDeleteResponse(BaseModel):
    userId: str
    deletionRequestId: str
    tombstoneId: str
    deletedAtUtc: str
    retainUntilUtc: str
