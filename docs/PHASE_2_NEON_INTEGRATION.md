# Phase 2 — Neon DEV Integration

**Repository:** `verigence/verigence-security`  
**Branch:** `feature/neon-integration`  
**Status:** BLOCKED — Neon migration credential is not available to GitHub Actions  
**Last updated:** 2026-08-13

## Design-grounded target

The approved migration `migrations/0001_security_baseline_v1.3.sql` is the source of truth for this phase.
It already defines the module schema as:

```sql
CREATE SCHEMA IF NOT EXISTS security;
```

All baseline objects are explicitly created under `security.*`. Do not invent a different schema name and do not modify the approved v1.3 migration merely to make deployment succeed.

## Attempted integration

Commit `fbb7b12f6f4bd642567a42cf7d8bfa190100cf3a` added a guarded GitHub Actions workflow at `.github/workflows/neon-dev-schema.yml`.

Workflow run: `31628325152`

The workflow stopped at the credential guard because `MIGRATION_DATABASE_URL` was empty/unavailable in the Actions context.

**No PostgreSQL connection was made and no Neon database/schema/object was changed by this run.**

The repository currently has no GitHub Environments configured, so there is no environment-scoped secret available through that mechanism.

## Required input to continue

Provide the existing Neon direct PostgreSQL connection to GitHub Actions without committing it to the repository.

Preferred repository secret name, matching `.env.example`:

`MIGRATION_DATABASE_URL`

The value must be the direct Neon PostgreSQL URL usable by `psql`, for example a `postgresql://...` URL with SSL enabled. Do not paste the credential into source files or documentation.

If an existing Actions secret uses a different name, only the **secret name** is needed to update the workflow; the secret value must remain in GitHub.

## Safety behavior already implemented

Once the migration credential is available, the workflow will:

1. verify the credential is present without printing it;
2. use a PostgreSQL client;
3. refuse to continue if the `security` schema already contains relations;
4. apply the approved v1.3 migration with `ON_ERROR_STOP` inside a single transaction;
5. verify that the `security` schema exists;
6. compare the number of created Security tables with the approved migration source.

Any schema conflict or migration failure must remain a blocker and must not be solved by silently editing the approved baseline.
