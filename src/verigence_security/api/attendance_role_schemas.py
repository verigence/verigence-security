from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class AttendanceRoleMutationResponse(BaseModel):
    tenantId: str
    userId: str
    moduleKey: Literal["attendance"] = "attendance"
    roleKey: Literal["HRADMIN"] = "HRADMIN"
    changed: bool
    assignmentId: str | None
