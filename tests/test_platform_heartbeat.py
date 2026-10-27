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
