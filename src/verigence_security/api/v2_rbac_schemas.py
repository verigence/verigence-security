from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

OperatingRoleKey = Literal["PC", "TL", "PM", "CRM", "Executive"]
RoleClass = Literal["OPERATING", "ADMIN", "TEST"]
RoleStatus = Literal["ACTIVE", "INACTIVE"]


class RoleDefinitionResponse(BaseModel):
    roleKey: str
    roleClass: RoleClass
    displayName: str
    status: RoleStatus


class RolePermissionBundleResponse(BaseModel):
    roleKey: OperatingRoleKey
    permissions: list[str]


class TenantRolePermissionBundleResponse(RolePermissionBundleResponse):
    tenantId: str


class TenantRolePermissionBundlePutRequest(BaseModel):
    permissions: list[str] = Field(default_factory=list)


class OperatingRolePutRequest(BaseModel):
    roleKey: OperatingRoleKey


class OperatingRoleMutationResponse(BaseModel):
    tenantId: str
    userId: str
    changed: bool
    assignmentId: str | None
    roleKey: OperatingRoleKey | None
