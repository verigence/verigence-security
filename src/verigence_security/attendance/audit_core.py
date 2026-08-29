from __future__ import annotations

from uuid import UUID

import httpx

from verigence_security.attendance.config import AttendanceSettings
from verigence_security.attendance.schemas import AttendanceWorkContext
from verigence_security.attendance.security import AttendanceDependencyError


class AuditCoreAttendanceClient:
    def __init__(self, settings: AttendanceSettings) -> None:
        self.settings = settings

    def current_work_context(
        self,
        *,
        tenant_id: UUID,
        human_bearer_token: str,
    ) -> AttendanceWorkContext | None:
        """Return the user's active Audit Core operating context when one exists.

        A 404 is a valid result for a secondary-role-only user such as HRADMIN.
        Connectivity failures and other HTTP failures remain dependency errors.
        """
        if not self.settings.audit_core_base_url.strip():
            raise AttendanceDependencyError("Audit Core attendance context is not configured")
        try:
            response = httpx.get(
                f"{self.settings.audit_core_base_url.rstrip('/')}/v1/tenants/{tenant_id}/attendance-context/me",
                headers={"Authorization": f"Bearer {human_bearer_token}"},
                timeout=self.settings.downstream_timeout_seconds,
            )
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return AttendanceWorkContext.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise AttendanceDependencyError(
                "Attendance work-location context is temporarily unavailable"
            ) from exc
