from __future__ import annotations

from typing import Literal
from uuid import UUID

from pydantic import BaseModel


class AttendanceRoleMutationResponse(BaseModel):
    tenantId: UUID
    userId: UUID
    moduleKey: Literal["attendance"] = "attendance"
    roleKey: Literal["HRADMIN"] = "HRADMIN"
    changed: bool
    assignmentId: UUID | None
