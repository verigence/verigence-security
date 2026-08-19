from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class AuthorizationCheckRequest(BaseModel):
    clerkSubject: str = Field(min_length=1, max_length=255)
    tenantId: UUID | None = None
    permissionKey: str = Field(min_length=1, max_length=180)

    @model_validator(mode="after")
    def normalize_required_values(self) -> AuthorizationCheckRequest:
        self.clerkSubject = self.clerkSubject.strip()
        self.permissionKey = self.permissionKey.strip()
        if not self.clerkSubject or not self.permissionKey:
            raise ValueError("clerkSubject and permissionKey cannot be blank")
        return self


class AuthorizationCheckResponse(BaseModel):
    allowed: bool
    decision: Literal["ALLOW", "DENY"]
    reasonCode: str
    userId: UUID | None = None
    tenantId: UUID | None = None
    permissionKey: str
    moduleKey: str | None = None
    classification: str | None = None
    roleKey: str | None = None
