from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Annotated, Any
from uuid import UUID

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from verigence_security.attendance.config import get_attendance_settings
from verigence_security.attendance.security import (
    AttendanceAuthenticationError,
    AttendanceAuthorizationError,
    AttendanceDependencyError,
    SecurityAuthorizationClient,
    verify_human_token,
)

_bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True, slots=True)
class HumanPrincipal:
    subject: str


def bearer_token(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise AttendanceAuthenticationError("Missing Security human token")
    token = credentials.credentials.strip()
    if not token:
        raise AttendanceDependencyError("Missing Security human token")
    return token


def human_principal(token: Annotated[str, Depends(bearer_token)]) -> HumanPrincipal:
    verified = verify_human_token(token, get_attendance_settings())
    return HumanPrincipal(subject=str(verified.user_id))


class EmployeeSecurityClient:
    """Compatibility wrapper over the existing Attendance Security client."""

    def __init__(self) -> None:
        self._client = SecurityAuthorizationClient(get_attendance_settings())

    def require(
        self,
        *,
        user_id: str,
        permission_key: str,
        tenant_id: str | UUID | None = None,
    ) -> dict[str, Any]:
        resolved_tenant = UUID(str(tenant_id)) if tenant_id is not None else None
        return self._client.check(
            user_id=UUID(user_id),
            tenant_id=resolved_tenant,
            permission_key=permission_key,
        )

    def allowed(
        self,
        *,
        user_id: str,
        permission_key: str,
        tenant_id: str | UUID | None = None,
    ) -> bool:
        try:
            self.require(
                user_id=user_id,
                permission_key=permission_key,
                tenant_id=tenant_id,
            )
            return True
        except AttendanceAuthorizationError:
            return False


@lru_cache
def security_client() -> EmployeeSecurityClient:
    return EmployeeSecurityClient()
