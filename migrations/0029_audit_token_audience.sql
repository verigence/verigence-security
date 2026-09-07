-- Verigence Security v2 — register the 'audit' ServiceIntegration token audience.
--
-- The rule-engine (verigence/rule-engine, Railway service audit-api) verifies
-- Security-issued SERVICE_INTEGRATION tokens with aud=audit. ServiceIntegration
-- token issuance (POST /security/v1/service/token) only accepts an audience that
-- resolves through security.permissions.module_key, so the module has to own at
-- least one ACTIVE permission key. Audit Core requests these tokens to call the
-- rule-engine's phase-audit API; no operating/admin role bundle references these
-- keys and none should without a separate approved mapping decision.

BEGIN;

INSERT INTO security.permissions
(permission_key,module_key,resource_key,action_key,description,status,
 display_name,catalog_version,updated_at_utc)
VALUES
  ('audit.evaluation.run','audit','evaluation','run',
   'Trigger a rule-engine phase audit for a Subject.',
   'ACTIVE','Run Audit Evaluation','audit-1.0',CURRENT_TIMESTAMP),
  ('audit.finding.read','audit','finding','read',
   'Read rule-engine audit findings for a Subject.',
   'ACTIVE','Read Audit Findings','audit-1.0',CURRENT_TIMESTAMP)
ON CONFLICT (permission_key) DO UPDATE SET
  module_key=EXCLUDED.module_key,
  resource_key=EXCLUDED.resource_key,
  action_key=EXCLUDED.action_key,
  description=EXCLUDED.description,
  status='ACTIVE',
  display_name=EXCLUDED.display_name,
  catalog_version=EXCLUDED.catalog_version,
  updated_at_utc=CURRENT_TIMESTAMP;

DO $$
DECLARE audit_module_keys integer;
BEGIN
  SELECT count(*) INTO audit_module_keys
  FROM security.permissions
  WHERE module_key='audit' AND status='ACTIVE';

  IF audit_module_keys=0 THEN
    RAISE EXCEPTION 'audit token audience registration failed: module has no ACTIVE permission key';
  END IF;
END $$;

COMMIT;
