from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[2] / "scripts" / "apply_attendance_migrations.py"
SPEC = importlib.util.spec_from_file_location("attendance_migration_runner", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
migration_runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = migration_runner
SPEC.loader.exec_module(migration_runner)

Migration = migration_runner.Migration
apply_pending_migrations = migration_runner.apply_pending_migrations
validate_recorded_migrations = migration_runner.validate_recorded_migrations


def migration(tmp_path: Path, name: str, checksum: str) -> Migration:
    path = tmp_path / name
    path.write_text("SELECT 1;\n", encoding="utf-8")
    return Migration(name=name, path=path, sha256=checksum)


def test_recorded_checksum_change_is_rejected(tmp_path: Path) -> None:
    item = migration(tmp_path, "0001_attendance_phase1.sql", "a" * 64)
    with pytest.raises(RuntimeError, match="checksum changed"):
        validate_recorded_migrations([item], {item.name: "b" * 64})


def test_unknown_ledger_entry_is_rejected(tmp_path: Path) -> None:
    item = migration(tmp_path, "0001_attendance_phase1.sql", "a" * 64)
    with pytest.raises(RuntimeError, match="not present"):
        validate_recorded_migrations([item], {"0999_removed.sql": "c" * 64})


def test_pending_migration_is_applied_then_recorded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    item = migration(tmp_path, "0001_attendance_phase1.sql", "a" * 64)
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

    def fake_record(database_url: str, migration: Migration, revision: str) -> None:
        del database_url, revision
        recorded.append(migration.name)

    monkeypatch.setattr(migration_runner, "run_psql", fake_run_psql)
    monkeypatch.setattr(migration_runner, "record_migration", fake_record)

    applied = apply_pending_migrations(
        "postgresql://example",
        [item],
        {},
        "abc123",
    )

    assert applied == 1
    assert executed == [item.name]
    assert recorded == [item.name]
