"""Platform heartbeat (SuperAdmin System Health, 2026-10-27): CPU kept as the per-minute
peak and average; without a database it does nothing and never stops Security."""
from __future__ import annotations

import threading

import pytest

from verigence_security import platform_heartbeat as hb


def test_peak_and_average_cores_per_minute(monkeypatch: pytest.MonkeyPatch) -> None:
    readings = iter([
        {"cpu_seconds": 50.0, "memory": 100, "memory_limit": 800, "cpu_limit": 12.0},
        {"cpu_seconds": 60.0, "memory": 300, "memory_limit": 800, "cpu_limit": 12.0},
        {"cpu_seconds": 61.0, "memory": 200, "memory_limit": 800, "cpu_limit": 12.0},
    ])
    monkeypatch.setattr(hb, "read_container_usage", lambda: next(readings))
    beat = hb.PlatformHeartbeat(None, "security")
    base = 1_800_000_000.0 - (1_800_000_000.0 % 60)
    for offset in (0, 5, 10):
        beat.sample(base + offset)
    [bucket] = beat.minutes.values()
    assert bucket["max"] == pytest.approx(2.0)
    assert bucket["sum"] / bucket["n"] == pytest.approx(1.1)
    assert (bucket["mem"], bucket["mem_limit"], bucket["cpu_limit"]) == (300, 800, 12.0)


def test_usage_is_readable_in_any_container() -> None:
    assert hb.read_container_usage()["cpu_seconds"] is not None


def test_without_a_database_the_thread_starts_and_stops_cleanly() -> None:
    stop = threading.Event()
    thread = hb.start_platform_heartbeat(None, "security", stop, sample_seconds=0.01)
    stop.wait(0.1)
    stop.set()
    thread.join(timeout=5)
    assert not thread.is_alive()


def test_a_missing_boot_row_is_written_by_the_next_beat() -> None:
    executed: list[str] = []

    class _Result:
        def __init__(self, rowcount: int) -> None:
            self.rowcount = rowcount

    class _Conn:
        def execute(self, statement: object, params: object = None) -> _Result:
            sql = str(statement)
            executed.append(sql.split()[0])
            return _Result(0 if sql.startswith("UPDATE") else 1)

    class _Begin:
        def __enter__(self) -> _Conn:
            return _Conn()

        def __exit__(self, *exc: object) -> bool:
            return False

    class _Engine:
        def begin(self) -> _Begin:
            return _Begin()

    beat = hb.PlatformHeartbeat(_Engine(), "security")  # type: ignore[arg-type]
    beat.beat()
    assert executed == ["UPDATE", "INSERT"]


# ── the night's sleep (product owner 2026-11-13) ────────────────────────────

def test_the_sleep_window_is_half_past_midnight_to_eight_india_time(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import UTC, datetime
    from datetime import time as clock_time
    from zoneinfo import ZoneInfo

    ist = ZoneInfo("Asia/Kolkata")

    def at(hour: int, minute: int = 0) -> datetime:
        return datetime(2026, 11, 14, hour, minute, tzinfo=ist).astimezone(UTC)

    monkeypatch.setattr(hb, "SLEEP_WINDOW", hb.parse_sleep_window(hb.DEFAULT_SLEEP_WINDOW))
    assert (clock_time(0, 30), clock_time(8, 0)) == hb.SLEEP_WINDOW
    assert not hb.asleep(at(0, 29)) and hb.asleep(at(0, 30)) and hb.asleep(at(7, 59)) and not hb.asleep(at(8, 0))
    assert hb.parse_sleep_window("off") is None
    assert hb.parse_sleep_window("not a window") == (clock_time(0, 30), clock_time(8, 0))
    monkeypatch.setattr(hb, "SLEEP_WINDOW", None)
    assert not hb.asleep(at(3, 0))


def test_asleep_nothing_is_sampled_or_written(monkeypatch: pytest.MonkeyPatch) -> None:
    from datetime import time as clock_time

    calls: list[str] = []
    monkeypatch.setattr(hb.PlatformHeartbeat, "boot", lambda self: calls.append("boot"))
    monkeypatch.setattr(hb.PlatformHeartbeat, "sample", lambda self: calls.append("sample"))
    monkeypatch.setattr(hb.PlatformHeartbeat, "beat", lambda self, **_k: calls.append("beat"))
    monkeypatch.setattr(hb.PlatformHeartbeat, "stop", lambda self, *_a: calls.append("stop"))
    monkeypatch.setattr(hb, "BEAT_EVERY_SAMPLES", 2)
    monkeypatch.setattr(hb, "SLEEP_WINDOW", (clock_time(0, 0), clock_time(23, 59, 59)))  # asleep all day

    class Stop:
        """Lets the loop turn five times, then stops it."""

        turns = 0

        def wait(self, _seconds: float) -> bool:
            self.turns += 1
            return self.turns > 5

    thread = hb.start_platform_heartbeat(None, "security", Stop(), sample_seconds=0)  # type: ignore[arg-type]
    thread.join(timeout=5)
    assert calls == ["boot", "sample", "stop"]  # the start and the stop only

    calls.clear()
    monkeypatch.setattr(hb, "SLEEP_WINDOW", None)  # by day
    thread = hb.start_platform_heartbeat(None, "security", Stop(), sample_seconds=0)  # type: ignore[arg-type]
    thread.join(timeout=5)
    assert calls.count("sample") == 6 and calls.count("beat") == 2
