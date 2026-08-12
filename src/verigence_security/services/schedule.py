from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from verigence_security.core.errors import security_error


@dataclass(frozen=True, slots=True)
class ScheduleWindow:
    iso_day_of_week: int
    start_local_time: time
    end_local_time: time
    crosses_midnight: bool


@dataclass(frozen=True, slots=True)
class ScheduleDecision:
    local_time: datetime
    authorized_until_utc: datetime


def _window_bounds(day: date, window: ScheduleWindow, tz: ZoneInfo) -> tuple[datetime, datetime]:
    start = datetime.combine(day, window.start_local_time, tzinfo=tz)
    end_day = day + timedelta(days=1) if window.crosses_midnight else day
    end = datetime.combine(end_day, window.end_local_time, tzinfo=tz)
    return start, end


def evaluate_schedule(
    *,
    now_utc: datetime,
    timezone_iana: str,
    windows: list[ScheduleWindow],
    override_until_utc: datetime | None = None,
) -> ScheduleDecision:
    if override_until_utc and override_until_utc > now_utc:
        tz = ZoneInfo(timezone_iana)
        return ScheduleDecision(now_utc.astimezone(tz), override_until_utc)
    if not windows:
        raise security_error("ACCESS_SCHEDULE_MISSING")
    tz = ZoneInfo(timezone_iana)
    local_now = now_utc.astimezone(tz)
    candidate_days = [local_now.date(), local_now.date() - timedelta(days=1)]
    for day in candidate_days:
        iso = day.isoweekday()
        for window in windows:
            if window.iso_day_of_week != iso:
                continue
            start, end = _window_bounds(day, window, tz)
            if start <= local_now < end:
                return ScheduleDecision(local_now, end.astimezone(UTC))
    raise security_error("ACCESS_OUTSIDE_ALLOWED_TIME")
