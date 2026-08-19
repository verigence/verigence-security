from __future__ import annotations

from pydantic import BaseModel

from verigence_security.api.v2_rbac_schemas import OperatingRoleKey


class RoleAlignedGroupResponse(BaseModel):
    tenantId: str
    roleKey: OperatingRoleKey
    displayName: str
    memberCount: int


class RoleAlignedGroupUserResponse(BaseModel):
    userId: str
    displayName: str
    primaryEmail: str | None
    status: str
