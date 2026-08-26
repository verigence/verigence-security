from __future__ import annotations

from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, model_validator


class SecurityRetentionPolicyReference(BaseModel):
    status: str | None = None
    accessContextRetentionDays: int | None = None
    accessSessionRetentionDays: int | None = None
    securityEventRetentionDays: int | None = None


class SecurityHousekeepingCounts(BaseModel):
    accessContextEvaluations: int
    accessSessions: int
    securityEvents: int


class SecurityHousekeepingPreviewResponse(BaseModel):
    tenantId: UUID
    cutoffDate: date
    cutoffExclusiveUtc: datetime
    total: SecurityHousekeepingCounts
    eligible: SecurityHousekeepingCounts
    retentionPolicy: SecurityRetentionPolicyReference


class SecurityHousekeepingPurgeRequest(BaseModel):
    cutoffDate: date
    confirmationCutoffDate: date

    @model_validator(mode="after")
    def confirmation_must_match(self) -> SecurityHousekeepingPurgeRequest:
        if self.confirmationCutoffDate != self.cutoffDate:
            raise ValueError("Confirmation cutoff date must exactly match cutoffDate")
        return self


class SecurityHousekeepingPurgeResponse(BaseModel):
    tenantId: UUID
    cutoffDate: date
    deleted: SecurityHousekeepingCounts
    completedAtUtc: datetime
