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
    ) -> AttendanceWorkContext:
        if not self.settings.audit_core_base_url.strip():
            raise AttendanceDependencyError("Audit Core attendance context is not configured")
        try:
            response = httpx.get(
                f"{self.settings.audit_core_base_url.rstrip('/')}/v1/tenants/{tenant_id}/attendance-context/me",
                headers={"Authorization": f"Bearer {human_bearer_token}"},
                timeout=self.settings.downstream_timeout_seconds,
            )
            response.raise_for_status()
            return AttendanceWorkContext.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise AttendanceDependencyError(
                "Attendance work-location context is temporarily unavailable"
            ) from exc
