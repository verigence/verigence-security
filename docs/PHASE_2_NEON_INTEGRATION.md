# Phase 2 — Neon DEV Integration

**Repository:** `verigence/verigence-security`  
**Branch:** `feature/neon-integration`  
**Status:** VALIDATED — pending normal PR/CI promotion to `dev`  
**Last updated:** 2026-08-13

## 1. Design-grounded target

The approved migration `migrations/0001_security_baseline_v1.3.sql` remains the source of truth for this phase.
It defines the module schema as:

```sql
CREATE SCHEMA IF NOT EXISTS security;
```

All baseline objects are explicitly created under `security.*`.
No alternate schema name was introduced and the approved v1.3 migration was not modified to make deployment succeed.

Approved migration SHA-256:

`175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d`

## 2. Credential handling

The Neon DEV connection is available to GitHub Actions as repository secret `MIGRATION_DATABASE_URL`.
The secret value is not stored in source, workflow files, documentation, test code, or logs.

The workflow also supports `DEV_DATABASE_URL` as a fallback because that is the established Verigence DEV database secret name used by `verigence-di`.

## 3. Baseline creation evidence

Initial guarded attempts correctly failed before database access while no repository secret was available. No database change occurred during those attempts.

After `MIGRATION_DATABASE_URL` was configured, failed workflow run `31628924267` was rerun. The rerun:

1. resolved the GitHub Actions secret without printing it;
2. verified the approved v1.3 migration digest;
3. confirmed the `security` schema was absent/empty;
4. applied the unchanged v1.3 migration with `ON_ERROR_STOP` inside a single transaction;
5. validated successful schema creation.

Result:

```text
schema = security
tables = 27
migration = approved v1.3 digest verified
result = PASS
```

## 4. Repeatable structure validation

The Phase-2 workflow was then made safely repeatable. If the schema is empty it may apply the approved baseline; if it already contains the complete baseline, it does not reapply the migration and instead validates exact structure. A partially populated/drifted table set fails closed.

Successful workflow run:

`31630275529`

Validated directly from the approved migration against Neon DEV:

| Validation | Result |
|---|---:|
| Security schema | PASS |
| Exact approved table-name set | PASS |
| Tables | 27 |
| Explicit indexes declared by baseline | 7 |
| Foreign-key constraints | 56 |
| CHECK constraints | 57 |
| Approved migration SHA-256 | PASS |
| Silent migration/schema rewrite | NONE |

The workflow derives expected table/index/constraint evidence from the approved migration rather than maintaining a second invented schema definition.

## 5. Real repository integration tests

`tests/integration/test_neon_repository.py` runs against the real Neon PostgreSQL schema only when `TEST_DATABASE_URL` is supplied by the guarded workflow.

Successful run `31630275529`:

```text
4 passed
```

Covered behavior:

1. `SecurityRepository.tenant_status()` and `get_user_context()` against real PostgreSQL;
2. `SecurityRepository.lock_active_device()` using real `SELECT ... FOR UPDATE` row locking across two concurrent database sessions;
3. enforcement of the approved `actor_type` CHECK constraint;
4. enforcement of the approved USER → Security Principal foreign key.

Integration fixtures use generated UUIDs and are removed after each test. Test values are fixtures only; they are not Security policy defaults or new design decisions.

## 6. What Phase 2 does not change

This phase does not:

- change Security v1.3 schema semantics;
- add a follow-on migration;
- invent new tables, statuses, permissions or thresholds;
- resolve any open Security design item;
- configure the Railway runtime service;
- claim the Neon runtime pooler URL has been configured for Railway.

The direct Neon connection is proven for migration and integration validation. Runtime pooled connection configuration remains part of Railway DEV deployment work.

## 7. Promotion gate

Before this branch is merged to `dev`:

1. open a PR from `feature/neon-integration` to `dev`;
2. require the normal Security CI quality/design-integrity workflow to pass;
3. review the PR diff for accidental design/schema changes;
4. merge only after both the normal CI gate and this Phase-2 Neon validation are green.

After promotion, the next execution phase is **Phase 3 — Railway DEV deployment**.
