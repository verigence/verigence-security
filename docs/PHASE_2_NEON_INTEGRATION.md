# Phase 2 — Neon DEV Integration

**Repository:** `verigence/verigence-security`  
**Branch:** `feature/neon-integration`  
**Status:** BLOCKED — safe credential injection into GitHub Actions is still required  
**Last updated:** 2026-08-13

## Design-grounded target

The approved migration `migrations/0001_security_baseline_v1.3.sql` is the source of truth for this phase.
It already defines the module schema as:

```sql
CREATE SCHEMA IF NOT EXISTS security;
```

All baseline objects are explicitly created under `security.*`. Do not invent a different schema name and do not modify the approved v1.3 migration merely to make deployment succeed.

The approved migration SHA-256 remains:

`175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d`

## Attempts and evidence

### Attempt 1 — Security-specific repository secret

Commit `fbb7b12f6f4bd642567a42cf7d8bfa190100cf3a` added the guarded workflow at `.github/workflows/neon-dev-schema.yml`.

Workflow run: `31628325152`

Result: the workflow stopped at the credential guard because `MIGRATION_DATABASE_URL` was empty/unavailable in the Actions context.

### Attempt 2 — reuse established Verigence DEV secret convention

The existing `verigence-di` repository documents/uses the Actions secret name `DEV_DATABASE_URL` for Neon DEV.
The Security workflow was updated to accept either:

1. `MIGRATION_DATABASE_URL` (preferred Security migration secret), or
2. `DEV_DATABASE_URL` (existing Verigence DEV convention).

Workflow run: `31628924267`

Result: both secrets were empty/unavailable to `verigence-security`; the workflow again stopped before any PostgreSQL connection.

### Direct execution attempt

A DEV connection string was explicitly supplied by the project owner for this phase. It was used only as an ephemeral runtime input and was not written to GitHub, source, workflow files, logs, or documentation.

The local execution runtime could not resolve the Neon hostname because outbound DNS/network access is unavailable from that runtime. Therefore a direct PostgreSQL connection could not be established from the execution environment.

The GitHub connector available to the assistant can create/update repository files and workflows but does not expose an API for creating or updating GitHub Actions secrets. Committing a live database credential into the public repository, even temporarily, is prohibited by the project security discipline and is not an acceptable workaround.

**No Neon database/schema/object has been created or modified by any Phase-2 attempt recorded above.**

The repository currently has no GitHub Environments configured, so there is no environment-scoped secret available through that mechanism.

## Required input to continue

The Neon DEV connection must be made available to GitHub Actions as a repository secret in `verigence/verigence-security`.

Preferred name:

`MIGRATION_DATABASE_URL`

Existing Verigence fallback also supported:

`DEV_DATABASE_URL`

The value must be the Neon PostgreSQL URL usable for migration. The secret value must not be committed to source or documentation.

Once either secret exists, the previously failed Phase-2 workflow can be rerun without changing the approved migration.

## Safety behavior already implemented

Once the migration credential is available, the workflow will:

1. resolve `MIGRATION_DATABASE_URL` first, otherwise `DEV_DATABASE_URL`, without printing the value;
2. normalize supported SQLAlchemy PostgreSQL URL schemes only for `psql` compatibility;
3. verify the committed migration SHA-256 matches the approved v1.3 digest;
4. refuse to continue if the `security` schema already contains relations;
5. apply the approved v1.3 migration with `ON_ERROR_STOP` inside a single transaction;
6. verify that the `security` schema exists;
7. compare the number of created Security tables with the approved migration source.

Any schema conflict or migration failure remains a blocker and must not be solved by silently editing the approved baseline.
