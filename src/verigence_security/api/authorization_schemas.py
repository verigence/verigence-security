from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class AuthorizationCheckRequest(BaseModel):
    userId: UUID
    tenantId: UUID | None = None
    permissionKey: str = Field(min_length=1, max_length=180)

    @model_validator(mode="after")
    def normalize_required_values(self) -> AuthorizationCheckRequest:
        self.permissionKey = self.permissionKey.strip()
        if not self.permissionKey:
            raise ValueError("permissionKey cannot be blank")
        return self


MAX_BATCH_PERMISSIONS = 64


class AuthorizationBatchCheckRequest(BaseModel):
    """Several permission questions about one user, answered in one call."""

    userId: UUID
    tenantId: UUID | None = None
    permissionKeys: list[str] = Field(min_length=1, max_length=MAX_BATCH_PERMISSIONS)

    @model_validator(mode="after")
    def normalize_required_values(self) -> AuthorizationBatchCheckRequest:
        cleaned = [key.strip() for key in self.permissionKeys]
        if any(not key or len(key) > 180 for key in cleaned):
            raise ValueError("each permissionKey must be 1 to 180 characters")
        self.permissionKeys = cleaned
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


class AuthorizationBatchCheckResponse(BaseModel):
    """One decision per permission asked, in the order asked, each shaped like a single check."""

    decisions: list[AuthorizationCheckResponse]
