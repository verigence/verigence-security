-- Verigence Security v2 — DI canonical permission catalogue sync.
-- The four keys below exist in DI's implemented canonical Permission enum but were not
-- required by the Phase-1 operating-role bundles seeded in 0013. Register them in Security
-- for complete module discovery and SuperAdmin all-ACTIVE authority. Do not add them to any
-- operating/admin role bundle without a separate approved mapping decision.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,
 display_name,catalog_version,updated_at_utc)
VALUES
  ('di.document.delete','di','document','delete',
   'Delete a DI Document where DI policy explicitly permits destructive removal.',
   'ACTIVE','Delete DI Document','di-2.2',CURRENT_TIMESTAMP),
  ('di.unassigned_document.assign','di','unassigned_document','assign',
   'Assign an unassigned DI Document to a Subject.',
   'ACTIVE','Assign Unassigned DI Document','di-2.2',CURRENT_TIMESTAMP),
  ('di.subject_matching.write','di','subject_matching','write',
   'Register verified DI Subject identifiers/channel mappings.',
   'ACTIVE','Manage DI Subject Matching','di-2.2',CURRENT_TIMESTAMP),
  ('di.platform.whatsapp.admin','di','platform.whatsapp','admin',
   'Manage DI system WhatsApp routes and pre-Tenant quarantine.',
   'ACTIVE','Administer DI WhatsApp Platform','di-2.2',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO NOTHING;

DO $$
DECLARE missing_count integer;
BEGIN
  SELECT count(*) INTO missing_count
  FROM unnest(ARRAY[
    'di.document.delete',
    'di.unassigned_document.assign',
    'di.subject_matching.write',
    'di.platform.whatsapp.admin'
  ]::varchar[]) required(permission_key)
  LEFT JOIN security.permissions p
    ON p.permission_key=required.permission_key AND p.status='ACTIVE'
  WHERE p.permission_key IS NULL;

  IF missing_count<>0 THEN
    RAISE EXCEPTION 'DI permission catalogue sync failed: % canonical key(s) missing/non-ACTIVE',
      missing_count;
  END IF;
END $$;

COMMIT;
