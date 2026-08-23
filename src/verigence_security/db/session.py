from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from verigence_security.config import Settings


def _runtime_database_url(database_url: str) -> str:
    """Normalize Railway/Neon PostgreSQL URLs to the installed psycopg v3 driver.

    Railway and Neon commonly expose `postgres://` / `postgresql://` URLs. SQLAlchemy interprets
    bare `postgresql://` as the legacy psycopg2 DBAPI, while this service intentionally installs
    `psycopg[binary]` v3. Normalize only PostgreSQL URLs; leave any other supported SQLAlchemy URL
    unchanged for tests/tooling.
    """

    if database_url.startswith("postgresql+psycopg://"):
        return database_url
    if database_url.startswith("postgresql+asyncpg://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgresql+asyncpg://")
    if database_url.startswith("postgresql://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgresql://")
    if database_url.startswith("postgres://"):
        return "postgresql+psycopg://" + database_url.removeprefix("postgres://")
    return database_url


def _is_postgresql(database_url: str) -> bool:
    return database_url.startswith("postgresql+") or database_url.startswith("postgresql://")


@lru_cache(maxsize=8)
def _engine_for_url(database_url: str) -> Engine:
    options: dict[str, Any] = {
        "pool_pre_ping": True,
        "future": True,
    }
    if _is_postgresql(database_url):
        options.update(
            pool_timeout=5,
            connect_args={
                "connect_timeout": 5,
                "options": "-c statement_timeout=10000",
            },
        )
    return create_engine(database_url, **options)


def build_engine(settings: Settings) -> Engine | None:
    if not settings.database_url:
        return None
    # Reuse one Engine/pool per normalized URL. Creating an Engine per request would defeat the
    # Neon pooled-runtime design and leak connection pools across requests.
    return _engine_for_url(_runtime_database_url(settings.database_url))


@lru_cache(maxsize=8)
def _session_factory_for_url(database_url: str) -> sessionmaker[Session]:
    return sessionmaker(
        bind=_engine_for_url(database_url),
        expire_on_commit=False,
        autoflush=False,
    )


def build_session_factory(settings: Settings) -> sessionmaker[Session] | None:
    if not settings.database_url:
        return None
    return _session_factory_for_url(_runtime_database_url(settings.database_url))


def session_dependency(factory: sessionmaker[Session] | None) -> Generator[Session, None, None]:
    if factory is None:
        raise RuntimeError("Database is not configured")
    with factory() as session:
        yield session


def database_is_ready(settings: Settings) -> bool:
    try:
        engine = build_engine(settings)
        if engine is None:
            return False
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except (SQLAlchemyError, ImportError, ValueError):
        # Readiness must fail closed with HTTP 503 rather than raising HTTP 500 for a bad runtime
        # DB URL/driver/configuration. The underlying exception remains an operational concern.
        return False
