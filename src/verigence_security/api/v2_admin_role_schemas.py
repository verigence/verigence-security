from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class AdminRoleMutationResponse(BaseModel):
    userId: str
    roleKey: Literal["TenantAdmin", "ModuleAdmin"]
    scopeType: Literal["TENANT", "MODULE"]
    scopeId: str
    changed: bool
    assignmentId: str | None
