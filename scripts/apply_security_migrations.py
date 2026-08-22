from __future__ import annotations

import argparse
import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

APPROVED_BASELINE_SHA256 = (
    "175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d"
)
LEDGER_TABLE = "security.schema_migrations"


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
        raise RuntimeError(f"No Security migrations found in {directory}")

    names = [path.name for path in paths]
    prefixes = [name.split("_", 1)[0] for name in names]
    if len(set(prefixes)) != len(prefixes):
        raise RuntimeError("Duplicate Security migration number detected")

    migrations = [
        Migration(name=path.name, path=path, sha256=file_sha256(path))
        for path in paths
    ]
    baseline = migrations[0]
    if baseline.name != "0001_security_baseline_v1.3.sql":
        raise RuntimeError("Unexpected Security baseline migration")
    if baseline.sha256 != APPROVED_BASELINE_SHA256:
        raise RuntimeError("Approved Security baseline digest mismatch")
    return migrations


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

    result = subprocess.run(
        command,
        check=True,
        text=True,
        capture_output=capture,
    )
    return result.stdout.strip() if capture else ""


def ensure_ledger(database_url: str) -> None:
    run_psql(
        database_url,
        sql=f"""
        CREATE SCHEMA IF NOT EXISTS security;
        CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
          migration_name text PRIMARY KEY,
          sha256 char(64) NOT NULL,
          applied_at_utc timestamptz NOT NULL DEFAULT now(),
          applied_by_revision text NOT NULL
        );
        """,
    )


def read_ledger(database_url: str) -> dict[str, str]:
    output = run_psql(
        database_url,
        sql=(
            f"SELECT migration_name || '|' || sha256 FROM {LEDGER_TABLE} "
            "ORDER BY migration_name;"
        ),
        capture=True,
    )
    rows: dict[str, str] = {}
    for line in output.splitlines():
        if not line:
            continue
        name, checksum = line.split("|", 1)
        rows[name] = checksum
    return rows


def business_table_count(database_url: str) -> int:
    output = run_psql(
        database_url,
        sql="""
        SELECT count(*)
        FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='security'
          AND c.relkind IN ('r','p')
          AND c.relname <> 'schema_migrations';
        """,
        capture=True,
    )
    return int(output)


def verify_legacy_schema_ready_for_adoption(database_url: str) -> None:
    output = run_psql(
        database_url,
        sql="""
        SELECT CASE WHEN
          to_regclass('security.tenants') IS NOT NULL
          AND to_regclass('security.role_definitions') IS NOT NULL
          AND to_regclass('security.user_deletion_requests') IS NOT NULL
          AND to_regclass('security.deleted_user_tombstones') IS NOT NULL
          AND to_regclass('security.password_reset_attempts') IS NOT NULL
          AND EXISTS (
            SELECT 1
            FROM pg_constraint c
            JOIN pg_class t ON t.oid=c.conrelid
            JOIN pg_namespace n ON n.oid=t.relnamespace
            WHERE n.nspname='security'
              AND t.relname='users'
              AND c.contype='c'
              AND pg_get_constraintdef(c.oid) LIKE '%REJECTED%'
          )
        THEN 'READY' ELSE 'NOT_READY' END;
        """,
        capture=True,
    )
    if output != "READY":
        raise RuntimeError(
            "Existing Security schema is not at the approved legacy adoption state"
        )


def record_migration(
    database_url: str,
    migration: Migration,
    revision: str,
) -> None:
    run_psql(
        database_url,
        sql=(
            f"INSERT INTO {LEDGER_TABLE} "
            "(migration_name,sha256,applied_by_revision) VALUES ("
            f"{sql_literal(migration.name)},"
            f"{sql_literal(migration.sha256)},"
            f"{sql_literal(revision)}) "
            "ON CONFLICT (migration_name) DO NOTHING;"
        ),
    )


def validate_recorded_migrations(
    migrations: list[Migration],
    recorded: dict[str, str],
) -> None:
    expected = {migration.name: migration.sha256 for migration in migrations}
    unknown = sorted(set(recorded) - set(expected))
    if unknown:
        raise RuntimeError(
            "Migration ledger contains files not present in this revision: "
            + ", ".join(unknown)
        )

    changed = sorted(
        name for name, checksum in recorded.items() if expected[name] != checksum
    )
    if changed:
        raise RuntimeError(
            "Previously applied Security migration checksum changed: "
            + ", ".join(changed)
        )


def adopt_existing_schema(
    database_url: str,
    migrations: list[Migration],
    target_name: str,
    revision: str,
) -> int:
    target_index = next(
        (index for index, migration in enumerate(migrations) if migration.name == target_name),
        None,
    )
    if target_index is None:
        raise RuntimeError(f"Legacy adoption target does not exist: {target_name}")

    verify_legacy_schema_ready_for_adoption(database_url)
    adopted = migrations[: target_index + 1]
    values = ",\n".join(
        "("
        f"{sql_literal(migration.name)},"
        f"{sql_literal(migration.sha256)},"
        f"{sql_literal(revision)}"
        ")"
        for migration in adopted
    )
    run_psql(
        database_url,
        sql=(
            "BEGIN;\n"
            f"INSERT INTO {LEDGER_TABLE} "
            "(migration_name,sha256,applied_by_revision) VALUES\n"
            f"{values};\n"
            "COMMIT;"
        ),
    )
    return len(adopted)


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
        print(f"Applying pending Security migration {migration.name}")
        run_psql(database_url, file=migration.path)
        record_migration(database_url, migration, revision)
        applied += 1
    return applied


def migrate(
    database_url: str,
    migrations_dir: Path,
    revision: str,
    bootstrap_existing_through: str | None,
) -> tuple[int, int, str]:
    migrations = discover_migrations(migrations_dir)
    ensure_ledger(database_url)
    recorded = read_ledger(database_url)
    validate_recorded_migrations(migrations, recorded)

    adopted = 0
    if not recorded and business_table_count(database_url) > 0:
        if not bootstrap_existing_through:
            raise RuntimeError(
                "Existing Security schema has no migration ledger; explicit adoption is required"
            )
        adopted = adopt_existing_schema(
            database_url,
            migrations,
            bootstrap_existing_through,
            revision,
        )
        recorded = read_ledger(database_url)
        validate_recorded_migrations(migrations, recorded)

    applied = apply_pending_migrations(
        database_url,
        migrations,
        recorded,
        revision,
    )
    final = read_ledger(database_url)
    validate_recorded_migrations(migrations, final)

    pending = [migration.name for migration in migrations if migration.name not in final]
    if pending:
        raise RuntimeError("Security migrations remain pending: " + ", ".join(pending))
    return adopted, applied, migrations[-1].name


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply Security SQL migrations exactly once in filename order."
    )
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--migrations-dir", default="migrations")
    parser.add_argument("--revision", required=True)
    parser.add_argument("--bootstrap-existing-through")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    adopted, applied, head = migrate(
        args.database_url,
        Path(args.migrations_dir),
        args.revision,
        args.bootstrap_existing_through,
    )
    print(f"SECURITY_MIGRATION_LEDGER_ADOPTED={adopted}")
    print(f"SECURITY_MIGRATIONS_APPLIED={applied}")
    print(f"SECURITY_MIGRATION_HEAD={head}")
    print("SECURITY_FORWARD_ONLY_MIGRATIONS=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
