"""Night control window (product owner, 6 Nov 2026): 20:00 to 08:30 IST runs over midnight."""

from __future__ import annotations

from datetime import UTC, datetime, time

from verigence_security.services.night_control import IST, in_window

START, END = time(20, 0), time(8, 30)


def _ist(h: int, m: int) -> datetime:
    return datetime(2026, 11, 6, h, m, tzinfo=IST)


def test_the_night_runs_from_2000_to_0830_india_time_over_midnight():
    assert not in_window(_ist(19, 59), START, END)
    assert in_window(_ist(20, 0), START, END)
    assert in_window(_ist(23, 59), START, END)
    assert in_window(_ist(0, 0), START, END)
    assert in_window(_ist(8, 29), START, END)
    assert not in_window(_ist(8, 30), START, END)
    assert not in_window(_ist(13, 0), START, END)


def test_the_time_zone_of_the_clock_does_not_matter():
    # 14:45 UTC is 20:15 IST
    assert in_window(datetime(2026, 11, 6, 14, 45, tzinfo=UTC), START, END)
    assert not in_window(datetime(2026, 11, 6, 14, 15, tzinfo=UTC), START, END)


def test_a_daytime_window_also_works():
    assert in_window(_ist(13, 0), time(12, 0), time(14, 0))
    assert not in_window(_ist(14, 0), time(12, 0), time(14, 0))
