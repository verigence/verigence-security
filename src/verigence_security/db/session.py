from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from verigence_security.config import Settings


@lru_cache(maxsize=8)
def _engine_for_url(database_url: str) -> Engine:
    return create_engine(
        database_url,
        pool_pre_ping=True,
        future=True,
    )


def build_engine(settings: Settings) -> Engine | None:
    if not settings.database_url:
        return None
    # Reuse one Engine/pool per configured URL. Creating an Engine per request would defeat the
    # Neon pooled-runtime design and leak connection pools across requests.
    return _engine_for_url(settings.database_url)


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
    return _session_factory_for_url(settings.database_url)


def session_dependency(factory: sessionmaker[Session] | None) -> Generator[Session, None, None]:
    if factory is None:
        raise RuntimeError("Database is not configured")
    with factory() as session:
        yield session


def database_is_ready(settings: Settings) -> bool:
    engine = build_engine(settings)
    if engine is None:
        return False
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except SQLAlchemyError:
        return False
