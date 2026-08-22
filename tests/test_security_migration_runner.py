from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "apply_security_migrations.py"
SPEC = importlib.util.spec_from_file_location("security_migration_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
migration_runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration_runner)

Migration = migration_runner.Migration
adopt_existing_schema = migration_runner.adopt_existing_schema
apply_pending_migrations = migration_runner.apply_pending_migrations
sql_literal = migration_runner.sql_literal
validate_recorded_migrations = migration_runner.validate_recorded_migrations


def migration(tmp_path: Path, name: str, checksum: str) -> Migration:
    path = tmp_path / name
    path.write_text("SELECT 1;\n", encoding="utf-8")
    return Migration(name=name, path=path, sha256=checksum)


def test_apply_pending_skips_recorded_migrations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = migration(tmp_path, "0001_security_baseline_v1.3.sql", "a" * 64)
    second = migration(tmp_path, "0002_next.sql", "b" * 64)
    executed: list[str] = []
    recorded: list[str] = []

    def fake_run_psql(
        database_url: str,
        *,
        sql: str | None = None,
        file: Path | None = None,
        capture: bool = False,
    ) -> str:
        del database_url, sql, capture
        if file is not None:
            executed.append(file.name)
        return ""

    def fake_record(
        database_url: str,
        item: Migration,
        revision: str,
    ) -> None:
        del database_url, revision
        recorded.append(item.name)

    monkeypatch.setattr(migration_runner, "run_psql", fake_run_psql)
    monkeypatch.setattr(migration_runner, "record_migration", fake_record)

    applied = apply_pending_migrations(
        "postgresql://example",
        [first, second],
        {first.name: first.sha256},
        "abc123",
    )

    assert applied == 1
    assert executed == [second.name]
    assert recorded == [second.name]


def test_recorded_checksum_change_is_rejected(tmp_path: Path) -> None:
    item = migration(tmp_path, "0001_security_baseline_v1.3.sql", "a" * 64)

    with pytest.raises(RuntimeError, match="checksum changed"):
        validate_recorded_migrations([item], {item.name: "b" * 64})


def test_unknown_ledger_entry_is_rejected(tmp_path: Path) -> None:
    item = migration(tmp_path, "0001_security_baseline_v1.3.sql", "a" * 64)

    with pytest.raises(RuntimeError, match="not present"):
        validate_recorded_migrations(
            [item],
            {"0999_removed.sql": "c" * 64},
        )


def test_legacy_adoption_is_one_atomic_insert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = migration(tmp_path, "0001_security_baseline_v1.3.sql", "a" * 64)
    second = migration(tmp_path, "0002_next.sql", "b" * 64)
    third = migration(tmp_path, "0003_future.sql", "c" * 64)
    sql_calls: list[str] = []

    monkeypatch.setattr(
        migration_runner,
        "verify_legacy_schema_ready_for_adoption",
        lambda database_url: None,
    )

    def fake_run_psql(
        database_url: str,
        *,
        sql: str | None = None,
        file: Path | None = None,
        capture: bool = False,
    ) -> str:
        del database_url, file, capture
        assert sql is not None
        sql_calls.append(sql)
        return ""

    monkeypatch.setattr(migration_runner, "run_psql", fake_run_psql)

    adopted = adopt_existing_schema(
        "postgresql://example",
        [first, second, third],
        second.name,
        "abc123",
    )

    assert adopted == 2
    assert len(sql_calls) == 1
    statement = sql_calls[0]
    assert statement.startswith("BEGIN;\n")
    assert statement.endswith("COMMIT;")
    assert first.name in statement
    assert second.name in statement
    assert third.name not in statement
    assert statement.count("abc123") == 2


def test_sql_literal_escapes_single_quotes() -> None:
    assert sql_literal("release'42") == "'release''42'"
