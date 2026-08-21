-- Verigence Security UC02 Phase-1 Tenant hard delete support.
-- Historical Security audit evidence retains the Tenant UUID after the live Tenant row is deleted.
-- Only the two reviewed historical-evidence tables are detached from the live Tenant FK.

BEGIN;

DO $$
DECLARE
  fk record;
BEGIN
  FOR fk IN
    SELECT con.conname AS constraint_name,
           tbl.relname AS table_name
    FROM pg_constraint con
    JOIN pg_class tbl ON tbl.oid=con.conrelid
    JOIN pg_namespace ns ON ns.oid=tbl.relnamespace
    WHERE con.contype='f'
      AND con.confrelid='security.tenants'::regclass
      AND ns.nspname='security'
      AND tbl.relname IN ('admin_change_records','security_events')
  LOOP
    EXECUTE format(
      'ALTER TABLE security.%I DROP CONSTRAINT %I',
      fk.table_name,
      fk.constraint_name
    );
  END LOOP;
END $$;

COMMENT ON COLUMN security.admin_change_records.tenant_id IS
  'Historical Tenant UUID. UC02 hard delete intentionally retains this value after the live Tenant row is removed.';

COMMENT ON COLUMN security.security_events.tenant_id IS
  'Historical Tenant UUID. UC02 hard delete intentionally retains this value after the live Tenant row is removed.';

COMMIT;
