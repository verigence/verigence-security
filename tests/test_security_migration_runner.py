from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "apply_security_migrations.py"
SPEC = importlib.util.spec_from_file_location("security_migration_runner", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

Migration = MODULE.Migration


def migration(tmp_path: Path, name: str, checksum: str):
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

    def fake_record(database_url: str, item, revision: str) -> None:
        del database_url, revision
        recorded.append(item.name)

    monkeypatch.setattr(MODULE, "run_psql", fake_run_psql)
    monkeypatch.setattr(MODULE, "record_migration", fake_record)

    applied = MODULE.apply_pending_migrations(
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
        MODULE.validate_recorded_migrations([item], {item.name: "b" * 64})


def test_unknown_ledger_entry_is_rejected(tmp_path: Path) -> None:
    item = migration(tmp_path, "0001_security_baseline_v1.3.sql", "a" * 64)

    with pytest.raises(RuntimeError, match="not present"):
        MODULE.validate_recorded_migrations(
            [item],
            {"0999_removed.sql": "c" * 64},
        )


def test_legacy_adoption_records_only_through_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = migration(tmp_path, "0001_security_baseline_v1.3.sql", "a" * 64)
    second = migration(tmp_path, "0002_next.sql", "b" * 64)
    third = migration(tmp_path, "0003_future.sql", "c" * 64)
    recorded: list[str] = []

    monkeypatch.setattr(
        MODULE,
        "verify_legacy_schema_ready_for_adoption",
        lambda database_url: None,
    )

    def fake_record(database_url: str, item, revision: str) -> None:
        del database_url, revision
        recorded.append(item.name)

    monkeypatch.setattr(MODULE, "record_migration", fake_record)

    adopted = MODULE.adopt_existing_schema(
        "postgresql://example",
        [first, second, third],
        second.name,
        "abc123",
    )

    assert adopted == 2
    assert recorded == [first.name, second.name]


def test_sql_literal_escapes_single_quotes() -> None:
    assert MODULE.sql_literal("release'42") == "'release''42'"


def test_script_loaded_as_module() -> None:
    assert isinstance(MODULE, ModuleType)
