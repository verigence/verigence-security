from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class AttendanceTenantSummary(BaseModel):
    tenantId: UUID
    tenantCode: str
    tenantName: str


class AttendanceTenantDirectoryResponse(BaseModel):
    items: list[AttendanceTenantSummary]


class AttendanceRosterMember(BaseModel):
    userId: UUID
    displayName: str
    primaryEmail: str | None = None
    operatingRole: str | None = None


class AttendanceRosterResponse(BaseModel):
    tenantId: UUID
    items: list[AttendanceRosterMember]
