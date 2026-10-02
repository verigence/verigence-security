from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Connection, Engine, create_engine

from verigence_security.attendance.db import sqlalchemy_database_url
from verigence_security.attendance.employee.settings import get_settings


@lru_cache
def employee_attendance_engine() -> Engine:
    """Small independent pool so Employee workloads cannot starve core Attendance."""
    return create_engine(
        sqlalchemy_database_url(get_settings().database_url),
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=1,
        pool_timeout=2,
        pool_recycle=600,
        pool_use_lifo=True,
    )


def get_connection() -> Iterator[Connection]:
    with employee_attendance_engine().begin() as connection:
        yield connection
