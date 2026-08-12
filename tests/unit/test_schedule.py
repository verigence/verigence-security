from datetime import UTC, datetime, time

import pytest

from verigence_security.core.errors import SecurityError
from verigence_security.services.schedule import ScheduleWindow, evaluate_schedule


def test_normal_window():
    now = datetime(2026,8,12,6,0,tzinfo=UTC)  # 11:30 Asia/Kolkata, Wednesday
    win = ScheduleWindow(3,time(9,0),time(18,0),False)
    decision = evaluate_schedule(now_utc=now, timezone_iana="Asia/Kolkata", windows=[win])
    assert decision.local_time.hour == 11


def test_outside_window_denied():
    now = datetime(2026,8,12,1,0,tzinfo=UTC)  # 06:30 local
    win = ScheduleWindow(3,time(9,0),time(18,0),False)
    with pytest.raises(SecurityError) as exc:
        evaluate_schedule(now_utc=now, timezone_iana="Asia/Kolkata", windows=[win])
    assert exc.value.code == "ACCESS_OUTSIDE_ALLOWED_TIME"


def test_overnight_window():
    # Friday 01:00 Asia/Kolkata, authorized by Thursday 20:00-04:00
    now = datetime(2026,8,13,19,30,tzinfo=UTC)
    thursday = 4
    win = ScheduleWindow(thursday,time(20,0),time(4,0),True)
    decision = evaluate_schedule(now_utc=now, timezone_iana="Asia/Kolkata", windows=[win])
    assert decision.authorized_until_utc > now
