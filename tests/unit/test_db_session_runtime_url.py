from __future__ import annotations

from verigence_security.db.session import _runtime_database_url


def test_railway_postgresql_url_uses_installed_psycopg_v3_driver() -> None:
    assert (
        _runtime_database_url("postgresql://user:secret@db.example/security?sslmode=require")
        == "postgresql+psycopg://user:secret@db.example/security?sslmode=require"
    )


def test_legacy_postgres_alias_uses_installed_psycopg_v3_driver() -> None:
    assert (
        _runtime_database_url("postgres://user:secret@db.example/security")
        == "postgresql+psycopg://user:secret@db.example/security"
    )


def test_asyncpg_runtime_url_is_converted_for_sync_security_runtime() -> None:
    assert (
        _runtime_database_url("postgresql+asyncpg://user:secret@db.example/security")
        == "postgresql+psycopg://user:secret@db.example/security"
    )


def test_psycopg_runtime_url_is_unchanged() -> None:
    value = "postgresql+psycopg://user:secret@db.example/security"
    assert _runtime_database_url(value) == value


def test_non_postgresql_sqlalchemy_url_is_unchanged() -> None:
    assert _runtime_database_url("sqlite+pysqlite:///:memory:") == "sqlite+pysqlite:///:memory:"
