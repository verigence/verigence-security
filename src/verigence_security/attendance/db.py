from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from verigence_security.attendance.config import get_attendance_settings


@lru_cache
def attendance_engine() -> Engine:
    settings = get_attendance_settings()
    if not settings.database_url.strip():
        raise RuntimeError("ATTENDANCE_DATABASE_URL is required")
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_size=settings.db_pool_size,
        max_overflow=settings.db_max_overflow,
        pool_timeout=settings.db_pool_timeout_seconds,
        pool_recycle=600,
        pool_use_lifo=True,
    )


@lru_cache
def _session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=attendance_engine(), expire_on_commit=False, autoflush=False)


def attendance_session() -> Iterator[Session]:
    session = _session_factory()()
    try:
        yield session
    finally:
        session.close()
