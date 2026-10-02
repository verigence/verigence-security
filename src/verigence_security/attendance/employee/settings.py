from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from verigence_security.attendance.config import get_attendance_settings


@dataclass(frozen=True, slots=True)
class EmployeeAttendanceSettings:
    database_url: str
    timezone_iana: str


@lru_cache
def get_settings() -> EmployeeAttendanceSettings:
    attendance = get_attendance_settings()
    if not attendance.database_url.strip():
        raise RuntimeError("ATTENDANCE_DATABASE_URL is required")
    return EmployeeAttendanceSettings(
        database_url=attendance.database_url,
        timezone_iana=attendance.default_timezone,
    )
