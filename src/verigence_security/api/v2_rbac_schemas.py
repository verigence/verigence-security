from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

# The operating roles a Tenant may assign. Casing is the contract Audit Core
# sends on its operating-role call, so "Executive" is capitalised and the rest
# are codes. Kept in step with security.role_definitions, where migration 0046
# added REVIEWER, and with the CHECK on user_tenant_operating_roles.role_key.
OperatingRoleKey = Literal["PC", "TL", "PM", "CRM", "Executive", "REVIEWER"]
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
