from __future__ import annotations

import argparse
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

LEDGER_TABLE = "attendance.schema_migrations"


@dataclass(frozen=True)
class Migration:
    name: str
    path: Path
    sha256: str


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def discover_migrations(directory: Path) -> list[Migration]:
    paths = sorted(directory.glob("[0-9][0-9][0-9][0-9]_*.sql"))
    if not paths:
        raise RuntimeError(f"No Attendance migrations found in {directory}")
    names = [path.name for path in paths]
    prefixes = [name.split("_", 1)[0] for name in names]
    if len(prefixes) != len(set(prefixes)):
        raise RuntimeError("Duplicate Attendance migration number detected")
    return [Migration(path=path, name=path.name, sha256=file_sha256(path)) for path in paths]


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def run_psql(
    database_url: str,
    *,
    sql: str | None = None,
    file: Path | None = None,
    capture: bool = False,
) -> str:
    if (sql is None) == (file is None):
        raise ValueError("Exactly one of sql or file must be supplied")
    command = ["psql", database_url, "-X", "-v", "ON_ERROR_STOP=1"]
    if sql is not None:
        command.extend(["-Atc", sql])
    else:
        command.extend(["-f", str(file)])
    result = subprocess.run(command, check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else ""


def ledger_exists(database_url: str) -> bool:
    return run_psql(
        database_url,
        sql="SELECT to_regclass('attendance.schema_migrations') IS NOT NULL;",
        capture=True,
    ) == "t"


def read_ledger(database_url: str) -> dict[str, str]:
    if not ledger_exists(database_url):
        return {}
    output = run_psql(
        database_url,
        sql=f"SELECT migration_name || '|' || sha256 FROM {LEDGER_TABLE} ORDER BY migration_name;",
        capture=True,
    )
    rows: dict[str, str] = {}
    for line in output.splitlines():
        if not line:
            continue
        name, checksum = line.split("|", 1)
        rows[name] = checksum
    return rows


def validate_recorded_migrations(
    migrations: list[Migration],
    recorded: dict[str, str],
) -> None:
    expected = {migration.name: migration.sha256 for migration in migrations}
    unknown = sorted(set(recorded) - set(expected))
    if unknown:
        raise RuntimeError(
            "Attendance migration ledger contains files not present in this revision: "
            + ", ".join(unknown)
        )
    changed = sorted(
        name for name, checksum in recorded.items() if expected[name] != checksum
    )
    if changed:
        raise RuntimeError(
            "Previously applied Attendance migration checksum changed: " + ", ".join(changed)
        )


def record_migration(database_url: str, migration: Migration, revision: str) -> None:
    if not ledger_exists(database_url):
        raise RuntimeError("Attendance migration did not create its migration ledger")
    run_psql(
        database_url,
        sql=(
            f"INSERT INTO {LEDGER_TABLE} (migration_name,sha256,applied_by_revision) VALUES ("
            f"{sql_literal(migration.name)},{sql_literal(migration.sha256)},{sql_literal(revision)}) "
            "ON CONFLICT (migration_name) DO NOTHING;"
        ),
    )


def apply_pending_migrations(
    database_url: str,
    migrations: list[Migration],
    recorded: dict[str, str],
    revision: str,
) -> int:
    applied = 0
    for migration in migrations:
        if migration.name in recorded:
            continue
        print(f"Applying pending Attendance migration {migration.name}")
        run_psql(database_url, file=migration.path)
        record_migration(database_url, migration, revision)
        applied += 1
    return applied


def migrate(database_url: str, migrations_dir: Path, revision: str) -> int:
    migrations = discover_migrations(migrations_dir)
    recorded = read_ledger(database_url)
    validate_recorded_migrations(migrations, recorded)
    applied = apply_pending_migrations(database_url, migrations, recorded, revision)
    final = read_ledger(database_url)
    validate_recorded_migrations(migrations, final)
    missing = [migration.name for migration in migrations if migration.name not in final]
    if missing:
        raise RuntimeError("Attendance migrations were not recorded: " + ", ".join(missing))
    return applied


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--migrations-dir", default="attendance_migrations")
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    applied = migrate(args.database_url, Path(args.migrations_dir), args.revision)
    print(f"ATTENDANCE_MIGRATIONS=PASS applied={applied}")


if __name__ == "__main__":
    main()
