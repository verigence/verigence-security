-- Verigence Security v2: the old PC attendance service is retired; attendance now lives in the HR
-- service (schema hr). The old schema is renamed rather than dropped so nothing is lost: once
-- nobody needs the history it can be removed with DROP SCHEMA attendance_retired CASCADE.
-- Idempotent: does nothing when there is no attendance schema or it was already renamed.

BEGIN;

DO $$
BEGIN
  IF to_regnamespace('attendance') IS NOT NULL AND to_regnamespace('attendance_retired') IS NULL THEN
    ALTER SCHEMA attendance RENAME TO attendance_retired;
  END IF;
END
$$;

COMMIT;
