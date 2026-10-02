from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class AttendanceFinanceRoleMutationResponse(BaseModel):
    userId: str
    moduleKey: Literal["attendance"] = "attendance"
    roleKey: Literal["FINANCEADMIN"] = "FINANCEADMIN"
    changed: bool
    assignmentId: str | None
