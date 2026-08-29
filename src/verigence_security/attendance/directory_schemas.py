from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel


class AttendanceTenantSummary(BaseModel):
    tenantId: UUID
    tenantCode: str
    tenantName: str


class AttendanceTenantDirectoryResponse(BaseModel):
    items: list[AttendanceTenantSummary]
