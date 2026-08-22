# Security Migration Runner v1.0

Security deployments must apply SQL migrations exactly once and in filename order.

## Rules

1. Historical migration files are immutable after application.
2. `scripts/apply_security_migrations.py` owns migration discovery, checksums, the migration ledger, and pending-only execution.
3. Applied migrations are recorded in `security.schema_migrations` with filename, SHA-256, application time, and deployment revision.
4. A checksum mismatch for an already-recorded migration is a deployment failure.
5. An existing Security schema without a ledger is never silently assumed current. It requires explicit legacy adoption through a named migration and must pass the runner's current-state adoption checks.
6. The existing DEV schema is adopted through `0024_uc02_tenant_hard_delete.sql`; subsequent migrations are executed only when absent from the ledger.
7. Fresh databases execute `0001` onward normally and record each successful migration.
8. Deployment continues to run the existing post-migration Security invariants before building or attaching a Railway image.

This prevents deployment-time replay of historical migrations such as `0003_global_user_onboarding_v1.4.2.sql`, whose historical USER lifecycle constraint is intentionally superseded by later migrations.
