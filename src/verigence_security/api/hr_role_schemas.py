from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class HrRoleMutationResponse(BaseModel):
    userId: str
    moduleKey: Literal["hr"] = "hr"
    roleKey: Literal["HRADMIN", "FINANCEADMIN", "CEO"]
    changed: bool
    assignmentId: str | None


class HrRolesResponse(BaseModel):
    userId: str
    moduleKey: Literal["hr"] = "hr"
    roles: list[Literal["HRADMIN", "FINANCEADMIN", "CEO"]]
